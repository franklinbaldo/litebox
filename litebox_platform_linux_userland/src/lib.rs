// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.

// Restrict this crate to only work on Linux. For now, we are restricting this to only x86-64 and
// aarch64 Linux, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::cell::Cell;
use std::io::IsTerminal as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;
use std::unimplemented;

use litebox::fs::OFlags;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{
    CowAllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer as _};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, vmap::VmapManager};

use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

/// [`litebox_common_linux::AT_FDCWD`] in the `usize` encoding the raw
/// `syscallN` helpers take: resolve relative paths against the current working
/// directory.
///
/// `openat` is used in place of `open` throughout this crate because AArch64
/// has no `open` syscall; with `AT_FDCWD` the two are equivalent on x86-64.
const AT_FDCWD: usize = (litebox_common_linux::AT_FDCWD as isize).cast_unsigned();

// ---------------------------------------------------------------------------
// TLS (`.tbss`) access helpers
//
// On x86_64, the ELF TLS model uses `@tpoff`; on x86 it uses `@ntpoff`.
// At guest-host transitions we swap `fs` and `gs`, so after the swap the host TLS base
// is in the normal segment register. Before the swap (e.g. in a signal
// handler that fires while the guest is running), the host TLS base is
// in the *saved* segment register (`gs` on x86_64, `fs` on x86).
//
// The macros below produce string literals so they can be used inside
// `concat!()` within `core::arch::asm!()`.
// ---------------------------------------------------------------------------

/// TLS relocation suffix: `"@tpoff"` on x86_64, `"@ntpoff"` on x86.
#[cfg(target_arch = "x86_64")]
macro_rules! tls_suffix {
    () => {
        "@tpoff"
    };
}

/// Segment register used for TLS after the fs/gs swap (normal host context).
#[cfg(target_arch = "x86_64")]
macro_rules! tls_seg {
    () => {
        "fs"
    };
}

/// Segment register where the host TLS base is saved before the swap
/// (signal handler context while the guest is running).
#[cfg(target_arch = "x86_64")]
macro_rules! saved_tls_seg {
    () => {
        "gs"
    };
}

/// Full TLS memory operand for a `.tbss` variable in normal host context
/// (after the fs/gs swap).
///
/// Example: `tls!("pending_host_signals")` expands to
/// `"fs:pending_host_signals@tpoff"` on x86_64.
///
/// AArch64 has no segment-relative addressing; it reads `TPIDR_EL0` into a
/// scratch register and applies a literal offset from [`tls_offset`] instead.
#[cfg(target_arch = "x86_64")]
macro_rules! tls {
    ($var:literal) => {
        concat!(tls_seg!(), ":", $var, tls_suffix!())
    };
}

/// Full TLS memory operand for a `.tbss` variable accessed via the *saved*
/// segment register (before the fs/gs swap, e.g. from a signal handler).
///
/// Example: `saved_tls!("in_guest")` expands to
/// `"gs:in_guest@tpoff"` on x86_64.
///
/// x86-64 only: it expands via `saved_tls_seg!`, and AArch64 has no saved
/// segment register to address through — `TPIDR_EL0` is the host anchor in
/// signal handlers already.
#[cfg(target_arch = "x86_64")]
macro_rules! saved_tls {
    ($var:literal) => {
        concat!(saved_tls_seg!(), ":", $var, tls_suffix!())
    };
}

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct LinuxUserland {
    tun_socket_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
    /// CoW-eligible memory regions. Maps start address of the static slice, to the info needed to
    /// re-mmap the file.
    cow_regions: std::sync::RwLock<std::collections::BTreeMap<usize, CowRegionInfo>>,
    /// If [`Self::initialize_boot_specific_kdf_support`] has been run, this is set to a value that
    /// is persistent across multiple process executions, however, it is ephemeral across true
    /// reboots.
    boot_id: std::sync::OnceLock<Vec<u8>>,
    stdio_is_tty: [bool; 3],
}

impl core::fmt::Debug for LinuxUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinuxUserland").finish_non_exhaustive()
    }
}

/// Information about a CoW-eligible memory region backed by a file.
#[derive(Debug, Clone)]
struct CowRegionInfo {
    /// The path to the backing file on the host filesystem.
    file_path: PathBuf,
    /// Length of the backing file.
    file_length: usize,
}

const IF_NAMESIZE: usize = 16;
/// Use TUN device
const IFF_TUN: i32 = 0x0001;
/// Do not provide packet information
const IFF_NO_PI: i32 = 0x1000;
/// libc `ifreq` structure, used for TUN/TAP devices.
#[repr(C)]
struct Ifreq {
    /// interface name, e.g. "en0"
    pub ifr_name: [i8; IF_NAMESIZE],
    pub ifr_ifru: Ifru,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifmap {
    mem_start: usize,
    mem_end: usize,
    base_addr: u16,
    irq: u8,
    dma: u8,
    port: u8,
}

/// libc `ifreq.ifr_ifru` union, used for TUN/TAP devices.
///
/// We only need `ifru_flags` for now; `ifru_map` is to ensure the size of the union
/// matches libc.
#[repr(C)]
pub union Ifru {
    // pub ifru_addr: crate::sockaddr,
    // pub ifru_dstaddr: crate::sockaddr,
    // pub ifru_broadaddr: crate::sockaddr,
    // pub ifru_netmask: crate::sockaddr,
    // pub ifru_hwaddr: crate::sockaddr,
    ifru_flags: i16,
    // pub ifru_ifindex: i32,
    // pub ifru_metric: i32,
    // pub ifru_mtu: i32,
    ifru_map: Ifmap,
    // pub ifru_slave: [i8; IF_NAMESIZE],
    // pub ifru_newname: [i8; IF_NAMESIZE],
    // pub ifru_data: *mut i8,
}

impl LinuxUserland {
    /// Create a new userland-Linux platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun99"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        #[cfg(target_arch = "aarch64")]
        assert_tls_layout();

        register_exception_handlers();

        let tun_socket_fd = tun_device_name
            .map(|tun_device_name| {
                let tun_path = b"/dev/net/tun\0";
                let tun_fd = unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::openat,
                        AT_FDCWD,
                        tun_path.as_ptr() as usize,
                        (litebox::fs::OFlags::RDWR
                            | litebox::fs::OFlags::CLOEXEC
                            | litebox::fs::OFlags::NONBLOCK)
                            .bits() as usize,
                        litebox::fs::Mode::empty().bits() as usize,
                    )
                }
                .expect("failed to open tun device");

                let tunsetiff = |fd: usize, ifreq: *const Ifreq| {
                    let cmd =
                        litebox_common_linux::iow!(b'T', 202, size_of::<::core::ffi::c_int>());
                    unsafe {
                        syscalls::syscall3(syscalls::Sysno::ioctl, fd, cmd as usize, ifreq as usize)
                    }
                    .expect("failed to set TUN interface flags");
                };
                let ifreq = Ifreq {
                    ifr_name: {
                        let mut name = [0i8; 16];
                        assert!(tun_device_name.len() < 16); // Note: strictly-less-than 16, to ensure it fits
                        for (i, b) in tun_device_name.char_indices() {
                            let b = b as u32;
                            assert!(b < 128);
                            name[i] = i8::try_from(b).unwrap();
                        }
                        name
                    },
                    ifr_ifru: Ifru {
                        // IFF_NO_PI: no tun header
                        // IFF_TUN: create tun (i.e., IP)
                        ifru_flags: i16::try_from(IFF_TUN | IFF_NO_PI).unwrap(),
                    },
                };
                tunsetiff(tun_fd, &raw const ifreq);

                // By taking ownership, we are letting the drop handler automatically run `libc::close`
                // when necessary.
                unsafe { std::os::fd::OwnedFd::from_raw_fd(tun_fd.reinterpret_as_signed().trunc()) }
            })
            .into();

        let reserved_pages = Self::read_maps();
        let platform = Self {
            tun_socket_fd,
            reserved_pages,
            cow_regions: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            boot_id: std::sync::OnceLock::new(),
            stdio_is_tty: [
                std::io::stdin().is_terminal(),
                std::io::stdout().is_terminal(),
                std::io::stderr().is_terminal(),
            ],
        };
        Box::leak(Box::new(platform))
    }

    /// Initializes support for KDFs by using boot-specific uniqueness.
    ///
    /// NOTE: The boot-specific uniqueness is NOT secure against an adversary with code execution or
    /// file read permissions on the host file system, since other processes on the same system can
    /// also derive the exact same keys.
    ///
    /// # Panics
    ///
    /// Panics if some standard Linux kernel-provided files are not available/accessible.
    ///
    /// Panics if run more than once on the same platform instance.
    pub fn initialize_boot_specific_kdf_support(&self) {
        let parsed: Vec<u8> = std::fs::read("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim_ascii()
            .split(|&x| x == b'-')
            .flat_map(|chunk| {
                chunk
                    .chunks(2)
                    .map(|t| u8::from_str_radix(str::from_utf8(t).unwrap(), 16).unwrap())
            })
            .collect();
        assert_eq!(parsed.len(), 16);
        self.boot_id.set(parsed).unwrap();
    }

    /// Register a CoW-eligible memory region backed by a file.
    ///
    /// # Panics
    ///
    /// Panics if an overlapping region is already registered.
    pub fn register_cow_region(&self, data: &'static [u8], file_path: impl Into<PathBuf>) {
        let start = data.as_ptr() as usize;
        let info = CowRegionInfo {
            file_path: file_path.into(),
            file_length: data.len(),
        };

        let mut regions = self.cow_regions.write().unwrap();
        assert!(
            regions.range(start..start + data.len()).next().is_none(),
            "Attempting to register an overlapping region"
        );
        let old = regions.insert(start, info);
        assert!(old.is_none());
    }

    /// Look up the file backing a static slice for CoW mapping.
    ///
    /// Returns `Some((file_path, offset_in_file))` if the slice is backed by a registered
    /// CoW region, `None` otherwise.
    fn lookup_cow_region(&self, source_data: &'static [u8]) -> Option<(PathBuf, usize)> {
        let slice_start = source_data.as_ptr() as usize;
        let slice_len = source_data.len();

        let regions = self.cow_regions.read().unwrap();

        if let Some((&region_start, info)) = regions.range(..=slice_start).next_back() {
            let region_end = region_start.checked_add(info.file_length).unwrap();
            let slice_end = slice_start.checked_add(slice_len).unwrap();

            if slice_start >= region_start && slice_end <= region_end {
                return Some((info.file_path.clone(), slice_start - region_start));
            }
        }
        None
    }

    fn read_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        // TODO: this function is not guaranteed to return all allocated pages, as it may
        // allocate more pages after the mapping file is read. Missing allocated pages may
        // cause the program to crash when calling `mmap` or `mremap` with the `MAP_FIXED` flag later.
        // We should either fix `mmap` to handle this error, or let global allocator call this function
        // whenever it get more pages from the host.
        let path = c"/proc/self/maps";
        let fd = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                AT_FDCWD,
                path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let Ok(fd) = fd else {
            return alloc::vec::Vec::new();
        };
        let mut buf = [0u8; 8192];
        let mut total_read = 0;
        while total_read < buf.len() {
            let n = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::read,
                    fd,
                    buf.as_mut_ptr() as usize + total_read,
                    buf.len() - total_read,
                )
            }
            .expect("read failed");
            if n == 0 {
                break;
            }
            total_read += n;
        }
        assert!(total_read < buf.len(), "buffer too small");
        unsafe { syscalls::syscall1(syscalls::Sysno::close, fd) }.expect("close failed");

        let mut reserved_pages = alloc::vec::Vec::new();
        let s = core::str::from_utf8(&buf[..total_read]).expect("invalid UTF-8");
        for line in s.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let range = parts[0].split('-').collect::<Vec<&str>>();
            let start = usize::from_str_radix(range[0], 16).expect("invalid start address");
            let end = usize::from_str_radix(range[1], 16).expect("invalid end address");
            reserved_pages.push(start..end);
        }
        reserved_pages
    }

    #[expect(
        clippy::missing_panics_doc,
        reason = "panicking only on failures of documented linux contracts"
    )]
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        let tid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::gettid) }
            .try_into()
            .unwrap();
        let ppid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::getppid) }
            .try_into()
            .unwrap();
        litebox_common_linux::TaskParams {
            pid: tid,
            ppid,
            uid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getuid) }
                .try_into()
                .unwrap(),
            euid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::geteuid) }
                .try_into()
                .unwrap(),
            gid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getgid) }
                .try_into()
                .unwrap(),
            egid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getegid) }
                .try_into()
                .unwrap(),
        }
    }

    /// Wait until there is data available on the TUN device.
    ///
    /// # Panics
    ///
    /// Panics if the TUN device is not initialized.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let mut pfd = libc::pollfd {
            fd: tun_fd.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = unsafe {
            libc::poll(
                &raw mut pfd,
                1,
                timeout.map_or(-1, |t| {
                    let ms = t.as_millis();
                    i32::try_from(ms).unwrap_or(i32::MAX)
                }),
            )
        };
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(
        clippy::missing_panics_doc,
        reason = "the seccomp filter rules are hardcoded and not expected to fail"
    )]
    /// Installs the runner seccomp filter.
    ///
    /// Broker transport exceptions are restricted to the supplied descriptors.
    pub fn enable_seccomp_filter(
        positional_io_fds: &[std::os::fd::RawFd],
        shutdown_fds: &[std::os::fd::RawFd],
    ) {
        use seccompiler::{
            BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
            SeccompFilter, SeccompRule,
        };

        let mut rules = vec![
            // TUN and terminal
            (libc::SYS_read, vec![]),
            (libc::SYS_write, vec![]),
            (libc::SYS_poll, vec![]),
            // memory management
            (libc::SYS_mmap, vec![]),
            (libc::SYS_mprotect, vec![]),
            (libc::SYS_munmap, vec![]),
            (libc::SYS_mremap, vec![]),
            // signal
            (libc::SYS_rt_sigreturn, vec![]),
            (libc::SYS_sigaltstack, vec![]),
            (libc::SYS_tgkill, vec![]),
            (libc::SYS_timer_create, vec![]),
            (libc::SYS_timer_settime, vec![]),
            (libc::SYS_timer_delete, vec![]),
            // called by [pthread_create](https://codebrowser.dev/glibc/glibc/nptl/pthread_create.c.html#83) to set up signal handler
            // to support setuid et.al. functions (which we probably don't need, but include them in debug mode to suppress the warnings
            // about missing seccomp rules for these syscalls).
            #[cfg(debug_assertions)]
            (libc::SYS_rt_sigaction, vec![]),
            // TODO: also called by `next_signal_handler`, but I'm not sure if it's really needed.
            (libc::SYS_rt_sigprocmask, vec![]),
            // thread management
            (libc::SYS_exit, vec![]),
            (libc::SYS_exit_group, vec![]),
            (libc::SYS_clone3, vec![]),
            // sync
            (libc::SYS_futex, vec![]),
            // misc
            (libc::SYS_getrandom, vec![]),
            // required by std spawn
            (libc::SYS_rseq, vec![]),
            (libc::SYS_set_robust_list, vec![]),
            (libc::SYS_get_robust_list, vec![]),
            (libc::SYS_sched_getaffinity, vec![]),
            (libc::SYS_gettid, vec![]),
            (libc::SYS_madvise, vec![]),
            // required by libc allocator
            (libc::SYS_brk, vec![]),
            (libc::SYS_getpid, vec![]),
            // TODO: could be removed if we pre-open files (see `try_allocate_cow_pages`)
            //
            // The condition is on argument index 2 because `openat` takes
            // `(dirfd, path, flags, mode)` — flags are the *third* argument.
            // Conditioning on index 1 would test the path pointer and let
            // through `openat` with arbitrary flags.
            (
                libc::SYS_openat,
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(
                            2,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Eq,
                            u64::from(OFlags::RDONLY.bits()),
                        )
                        .unwrap(),
                    ])
                    .unwrap(),
                ],
            ),
            // Connected UnixStream I/O may use sendto/recvfrom rather than raw
            // read/write. Limit these rules to connected-socket calls that do
            // not name a peer address.
            (
                libc::SYS_sendto,
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(4, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                        SeccompCondition::new(5, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                    ])
                    .unwrap(),
                ],
            ),
            (
                libc::SYS_recvfrom,
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(4, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                        SeccompCondition::new(5, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                    ])
                    .unwrap(),
                ],
            ),
            (libc::SYS_close, vec![]),
        ];
        if !positional_io_fds.is_empty() {
            // Broker shared memory uses positional descriptor I/O.
            let fd_rules = || {
                positional_io_fds
                    .iter()
                    .map(|fd| {
                        SeccompRule::new(vec![
                            SeccompCondition::new(
                                0,
                                SeccompCmpArgLen::Dword,
                                SeccompCmpOp::Eq,
                                u64::from(
                                    u32::try_from(*fd)
                                        .expect("positional I/O descriptor must be valid"),
                                ),
                            )
                            .unwrap(),
                        ])
                        .unwrap()
                    })
                    .collect()
            };
            rules.push((libc::SYS_pread64, fd_rules()));
            rules.push((libc::SYS_pwrite64, fd_rules()));
        }
        if !shutdown_fds.is_empty() {
            // Association failure shuts down the control socket in both
            // directions to interrupt local and peer liveness waits.
            let shutdown_rules = shutdown_fds
                .iter()
                .map(|fd| {
                    SeccompRule::new(vec![
                        SeccompCondition::new(
                            0,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Eq,
                            u64::from(
                                u32::try_from(*fd).expect("shutdown descriptor must be valid"),
                            ),
                        )
                        .unwrap(),
                        SeccompCondition::new(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Eq,
                            u64::from(
                                u32::try_from(libc::SHUT_RDWR)
                                    .expect("SHUT_RDWR must be non-negative"),
                            ),
                        )
                        .unwrap(),
                    ])
                    .unwrap()
                })
                .collect();
            rules.push((libc::SYS_shutdown, shutdown_rules));
        }
        let rule_map: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
            rules.into_iter().collect();
        let filter = SeccompFilter::new(
            rule_map,
            // In debug builds, log violations instead of silently returning an error so that
            // it won't fail silently during development (which may be hard to debug).
            if cfg!(debug_assertions) {
                SeccompAction::Trap
            } else {
                SeccompAction::Errno(libc::EINVAL.cast_unsigned())
            },
            SeccompAction::Allow,
            {
                #[cfg(target_arch = "x86_64")]
                {
                    seccompiler::TargetArch::x86_64
                }
                #[cfg(target_arch = "aarch64")]
                {
                    seccompiler::TargetArch::aarch64
                }
            },
        )
        .unwrap();
        // TODO: bpf program can be compiled offline
        let bpf_prog: BpfProgram = filter.try_into().unwrap();

        seccompiler::apply_filter(&bpf_prog).unwrap();
    }
}

impl litebox::platform::Provider for LinuxUserland {}

impl litebox::platform::SignalProvider for LinuxUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let sigs = take_pending_host_signals();
        for sig in sigs {
            f(sig);
        }
    }
}

/// Atomically takes the per-thread pending host signal bitmask.
fn take_pending_host_signals() -> litebox_common_linux::signal::SigSet {
    // Atomically swap the per-thread pending signals with zero.
    // Only the low 32 bits are used (covers traditional signals 1-31).
    let lo: u32;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "xor {tmp:e}, {tmp:e}",
            concat!("xchg DWORD PTR ", tls!("pending_host_signals"), ", {tmp:e}"),
            tmp = out(reg) lo,
            options(nostack)
        );
    }
    // AArch64 has no `xchg`. The x86-64 `xchg` is an implicitly `lock`ed,
    // fully ordered read-modify-write, so match it with the standard
    // sequentially-consistent RMW mapping: an acquire exclusive load paired
    // with a release exclusive store (`ldaxr`/`stlxr`). Deliberately not
    // `swpal`, which requires LSE (ARMv8.1) and would raise the baseline this
    // crate runs on.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: reads and clears a naturally aligned `u32` in this thread's own
    // TLS control block, whose offset from `TPIDR_EL0` is checked by
    // `assert_tls_layout`.
    unsafe {
        core::arch::asm!(
            "mrs {addr}, tpidr_el0",
            "add {addr}, {addr}, #{off}",
            "2:",
            "ldaxr {val:w}, [{addr}]",
            "stlxr {status:w}, wzr, [{addr}]",
            "cbnz {status:w}, 2b",
            addr = out(reg) _,
            val = out(reg) lo,
            status = out(reg) _,
            off = const tls_offset::PENDING_HOST_SIGNALS,
            options(nostack)
        );
    }
    litebox_common_linux::signal::SigSet::from_u64(u64::from(lo))
}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates or returns.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(&shim, ctx, false);
}

/// Run a guest thread using a reference to the shim.
///
/// Unlike `run_thread`, this version takes a reference instead of ownership,
/// avoiding struct moves that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, false);
}

/// Re-enter a guest thread using a reference to the shim.
///
/// This version takes a reference instead of ownership, avoiding struct moves
/// that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn reenter_thread<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, true);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    reenter: bool,
) {
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    // Mark this thread as a guest thread for the duration of its guest
    // lifetime, so signal handlers can tell it apart from an ordinary host
    // thread. x86-64 gets this for free from `gsbase != 0`; see
    // `set_is_guest_thread`. Save and restore rather than unconditionally
    // clearing, so a nested entry (e.g. `reenter_thread` reached from inside a
    // shim callback) does not un-mark the thread while an outer frame is still
    // running the guest. The guard also runs on unwind, since `run_thread_arch`
    // is `extern "C-unwind"`.
    #[cfg(target_arch = "aarch64")]
    let was_guest_thread = is_guest_thread();
    #[cfg(target_arch = "aarch64")]
    set_is_guest_thread(true);
    #[cfg(target_arch = "aarch64")]
    let _guest_thread_guard = litebox::utils::defer(|| set_is_guest_thread(was_guest_thread));
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| unsafe {
            run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter));
        });
    });
}

/// Byte offsets of the AArch64 TLS control block from `TPIDR_EL0`.
///
/// These are hardcoded rather than materialized through `#:tprel_g1:` /
/// `#:tprel_g0_nc:` relocation pairs because `syscall_callback` is entered with
/// only `x16` free and cannot spare the second scratch register a relocation
/// pair needs. [`assert_tls_layout`] verifies them at startup.
#[cfg(target_arch = "aarch64")]
mod tls_offset {
    /// Guest thread pointer. Fixed by the rewriter ABI: must equal
    /// `litebox_syscall_rewriter`'s `arm64::GUEST_TPIDR_OFFSET`.
    pub(super) const GUEST_TPIDR: usize = 16;
    pub(super) const HOST_SP: usize = 24;
    pub(super) const GUEST_CONTEXT_TOP: usize = 32;
    pub(super) const IN_GUEST: usize = 40;
    pub(super) const INTERRUPT: usize = 41;
    /// Set for a thread's whole guest lifetime, not just while guest code is
    /// executing. This is the AArch64 analogue of x86-64's `gsbase != 0`
    /// probe; see [`super::interrupt_signal_handler`] for why `IN_GUEST` is
    /// not a substitute. Lives in what used to be alignment padding, so it
    /// perturbs no other offset.
    pub(super) const IS_GUEST_THREAD: usize = 42;
    pub(super) const PENDING_HOST_SIGNALS: usize = 44;
    pub(super) const WAIT_WAKER_ADDR: usize = 48;
}

// The block is emitted into `.tdata` so the linker places it ahead of every
// `.tbss` object, putting it at the head of the main executable's static TLS
// area and therefore at a known offset from the thread pointer. A `.tbss`
// placement measures at +48 instead of the required +16 on a stock Rust binary.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    "
    .section .tdata.litebox_tls, \"awT\", @progbits
    // `.align` is a power-of-two exponent on AArch64, so this is 16 bytes. The
    // nearby x86-64 block spells 8-byte alignment as `.align 8`; do not
    // 'harmonize' the two.
    .align 4
.globl guest_tpidr
guest_tpidr:
    .quad 0
.globl host_sp
host_sp:
    .quad 0
.globl guest_context_top
guest_context_top:
    .quad 0
.globl in_guest
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    // Occupies what was previously alignment padding between `interrupt` (41)
    // and `pending_host_signals` (44), so introducing it shifts no other
    // symbol and leaves every literal offset baked into the transition
    // assembly untouched. `assert_tls_layout` enforces that. Keep the
    // `.align 2` below: it is what still lands `pending_host_signals` at 44.
.globl is_guest_thread
is_guest_thread:
    .byte 0
    .align 2
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 3
.globl wait_waker_addr
wait_waker_addr:
    .quad 0
    "
);

/// Materializes the link-time thread-pointer-relative offset of a TLS symbol,
/// named either as a bare identifier or as a string literal.
#[cfg(target_arch = "aarch64")]
macro_rules! tprel_offset {
    ($var:ident) => {
        tprel_offset!(@sym stringify!($var))
    };
    ($var:literal) => {
        tprel_offset!(@sym $var)
    };
    (@sym $var:expr) => {{
        let offset: usize;
        // SAFETY: reads no memory; materializes a link-time constant only.
        unsafe {
            core::arch::asm!(
                concat!("movz {0}, #:tprel_g1:", $var),
                concat!("movk {0}, #:tprel_g0_nc:", $var),
                out(reg) offset,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        offset
    }};
}

/// Verifies that the TLS control block landed where [`tls_offset`] says it did.
///
/// The transition assembly addresses the block with literal offsets rather than
/// relocations, so a silent shift would corrupt host TLS or the guest thread
/// pointer at runtime. Panicking here converts that into a legible failure.
///
/// Two distinct things can shift the block. The obvious one is another TLS
/// object being linked ahead of `.tdata.litebox_tls`. The subtler one is
/// alignment: AArch64 uses TLS variant 1, where the static block starts at
/// `round_up(16, align(PT_TLS))`, and `align(PT_TLS)` is the maximum over
/// *every* TLS object in the link. So a single thread-local anywhere — in this
/// crate or any dependency — whose type wants more than 16-byte alignment
/// shifts the whole block, even while `.tdata.litebox_tls` is still first. A
/// cache-line-padded thread-local (`#[repr(align(64))]`) moves `guest_tpidr`
/// from 16 to 64.
///
/// # Panics
///
/// Panics if any symbol's actual offset differs from its expected offset.
#[cfg(target_arch = "aarch64")]
fn assert_tls_layout() {
    /// Compares one symbol's link-time offset against its expected constant.
    /// The symbol name is written once and reused for the lookup, the
    /// relocation and the message, so the three cannot drift apart.
    macro_rules! check {
        ($sym:ident, $expected:ident) => {{
            let actual = tprel_offset!($sym);
            let expected = tls_offset::$expected;
            assert!(
                actual == expected,
                "TLS symbol `{}` is at thread-pointer offset {actual}, expected {expected}; \
                 either another TLS object was linked ahead of `.tdata.litebox_tls`, or some \
                 TLS object in the link has alignment > 16, which shifts the whole static TLS \
                 block",
                stringify!($sym),
            );
        }};
    }

    check!(guest_tpidr, GUEST_TPIDR);
    check!(host_sp, HOST_SP);
    check!(guest_context_top, GUEST_CONTEXT_TOP);
    check!(in_guest, IN_GUEST);
    check!(interrupt, INTERRUPT);
    check!(is_guest_thread, IS_GUEST_THREAD);
    check!(pending_host_signals, PENDING_HOST_SIGNALS);
    check!(wait_waker_addr, WAIT_WAKER_ADDR);
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    "
    .section .tbss
    .align 8
scratch:
    .quad 0
host_sp:
    .quad 0
host_bp:
    .quad 0
guest_context_top:
    .quad 0
.globl guest_fsbase
guest_fsbase:
    .quad 0
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    .align 4
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 8
.globl wait_waker_addr
wait_waker_addr:
    .quad 0
    "
);

#[cfg(target_arch = "x86_64")]
fn set_guest_fsbase(value: usize) {
    unsafe {
        core::arch::asm! {
            "mov fs:guest_fsbase@tpoff, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn get_guest_fsbase() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm! {
            "mov {}, fs:guest_fsbase@tpoff",
            out(reg) value,
            options(nostack, preserves_flags)
        }
    }
    value
}

/// Writes the guest's virtualized thread pointer.
///
/// The hardware `TPIDR_EL0` always holds the *host* anchor, so the guest's
/// thread pointer lives in the runtime-owned slot beside it. The rewriter
/// redirects every guest `MSR TPIDR_EL0` to this same slot.
#[cfg(target_arch = "aarch64")]
fn set_guest_tpidr(value: usize) {
    // SAFETY: writes a naturally aligned `u64` in this thread's own TLS
    // control block, whose offset from `TPIDR_EL0` is checked by
    // `assert_tls_layout`.
    unsafe {
        core::arch::asm! {
            "mrs {tmp}, tpidr_el0",
            "str {val}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = in(reg) value,
            off = const tls_offset::GUEST_TPIDR,
            options(nostack, preserves_flags)
        }
    }
}

/// Marks (or unmarks) the current thread as a guest thread for the whole of
/// its guest lifetime.
///
/// This is the AArch64 stand-in for x86-64's `gsbase != 0` probe. On x86-64,
/// `gsbase` is non-zero from the moment a thread enters guest execution until
/// it leaves, which makes it a *thread-lifetime* property. AArch64 has no such
/// incidentally-repurposed register — `TPIDR_EL0` is valid on every thread in
/// the process, guest or not — so the property is recorded explicitly.
///
/// Deliberately a plain byte and not an atomic RMW: only the owning thread
/// ever writes this slot, and it is read either by that same thread or by a
/// signal handler running on it, so there is no cross-thread race to order
/// against.
#[cfg(target_arch = "aarch64")]
fn set_is_guest_thread(value: bool) {
    // SAFETY: writes a single byte in this thread's own TLS control block,
    // whose offset from `TPIDR_EL0` is checked by `assert_tls_layout`.
    unsafe {
        core::arch::asm! {
            "mrs {tmp}, tpidr_el0",
            "strb {val:w}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = in(reg) u32::from(value),
            off = const tls_offset::IS_GUEST_THREAD,
            options(nostack, preserves_flags)
        }
    }
}

/// Reads the current thread's guest-thread marker. See [`set_is_guest_thread`].
#[cfg(target_arch = "aarch64")]
fn is_guest_thread() -> bool {
    let value: u32;
    // SAFETY: reads a single byte in this thread's own TLS control block,
    // whose offset from `TPIDR_EL0` is checked by `assert_tls_layout`. Safe to
    // call from a signal handler: `TPIDR_EL0` is the host anchor at all times,
    // including while guest code runs.
    unsafe {
        core::arch::asm! {
            "mrs {tmp}, tpidr_el0",
            "ldrb {val:w}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = out(reg) value,
            off = const tls_offset::IS_GUEST_THREAD,
            options(nostack, preserves_flags)
        }
    }
    value != 0
}

/// Reads the guest's virtualized thread pointer. See [`set_guest_tpidr`].
#[cfg(target_arch = "aarch64")]
fn get_guest_tpidr() -> usize {
    let value: usize;
    // SAFETY: reads a naturally aligned `u64` in this thread's own TLS control
    // block, whose offset from `TPIDR_EL0` is checked by `assert_tls_layout`.
    unsafe {
        core::arch::asm! {
            "mrs {tmp}, tpidr_el0",
            "ldr {val}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = out(reg) value,
            off = const tls_offset::GUEST_TPIDR,
            options(nostack, preserves_flags)
        }
    }
    value
}

/// Runs the guest thread until it terminates.
///
/// This saves all non-volatile register state then switches to the guest
/// context. When the guest makes a syscall, it jumps back into the middle of
/// this routine, at `syscall_callback`. This code then updates the guest
/// context structure, switches back to the host stack, and calls the syscall
/// handler.
///
/// When the guest thread terminates, this function returns after restoring
/// non-volatile register state.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Push all non-volatiles.
    push rbp
    mov rbp, rsp
    .cfi_def_cfa rbp, 16
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi // save thread context

    // Save host rsp and rbp and guest context top in TLS.
    mov fs:host_sp@tpoff, rsp
    mov fs:host_bp@tpoff, rbp
    lea r8, [rsi + {GUEST_CONTEXT_SIZE}]
    mov fs:guest_context_top@tpoff, r8

    // Save host fs base in gs base. This will stay set for the lifetime
    // of this call stack.
    rdfsbase r8
    wrgsbase r8

    // Call init_handler or reenter_handler based on reenter flag (in dl).
    test dl, dl
    jnz 1f
    call {init_handler}
    jmp .Ldone
1:
    call {reenter_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl syscall_callback
syscall_callback:
    // Clear in_guest flag. This must be the first instruction to match the
    // expectations of `interrupt_signal_handler`.
    mov      BYTE PTR gs:in_guest@tpoff, 0

    // Restore host fs base.
    rdfsbase r11
    mov      gs:guest_fsbase@tpoff, r11
    rdgsbase r11
    wrfsbase r11

    // Switch to the top of the guest context.
    mov     r11, rsp
    mov     rsp, fs:guest_context_top@tpoff

    // TODO: save float and vector registers (xsave or fxsave)
    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    r11        // pt_regs->sp
    pushfq             // pt_regs->eflags
    push    0x33       // pt_regs->cs = __USER_CS
    push    rcx        // pt_regs->ip
    push    rax        // pt_regs->orig_ax

    push    rdi         // pt_regs->di
    push    rsi         // pt_regs->si
    push    rdx         // pt_regs->dx
    push    rcx         // pt_regs->cx
    push    -38         // pt_regs->ax = ENOSYS
    push    r8          // pt_regs->r8
    push    r9          // pt_regs->r9
    push    r10         // pt_regs->r10
    push    [rsp + 88]  // pt_regs->r11 = rflags
    push    rbx         // pt_regs->bx
    push    rbp         // pt_regs->bp
    push    r12         // pt_regs->r12
    push    r13         // pt_regs->r13
    push    r14         // pt_regs->r14
    push    r15         // pt_regs->r15

    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov rdi, [rsp] // pass thread_ctx
    call {syscall_handler}
    // This thread is done. Return.
    jmp .Ldone

exception_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {interrupt_handler}

.Ldone:

    lea  rsp, [rbp - 5*8]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    .cfi_def_cfa rsp, 8
    ret
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Runs the guest thread until it terminates.
///
/// Parallels the x86-64 version above: it saves the callee-saved registers,
/// publishes the host stack pointer and the top of the guest context into the
/// TLS control block, and dispatches to `init_handler` or `reenter_handler`.
/// When the guest issues a syscall it re-enters this function's body at
/// `syscall_callback`, which spills the guest state into the `PtRegs` block,
/// switches back to the host stack, and calls `syscall_handler`.
///
/// Unlike x86-64 there is **no thread-pointer swapping anywhere**. `TPIDR_EL0`
/// holds the host anchor for the entire lifetime of this call stack, including
/// while guest code runs; the rewriter redirects every guest thread-pointer
/// access to `[TPIDR_EL0 + 16]` (see [`tls_offset::GUEST_TPIDR`]). There is
/// therefore no `rdfsbase`/`wrgsbase` analogue to prime.
///
/// The `PtRegs` field offsets baked into the assembly below are pinned by
/// `tests::test_ptregs_layout`.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Save the frame pointer and link register, then the callee-saved GPRs.
    // 96 bytes covers x29/x30 plus x19-x28.
    stp x29, x30, [sp, #-96]!
    .cfi_def_cfa_offset 96
    .cfi_offset x29, -96
    .cfi_offset x30, -88
    mov x29, sp
    // Anchor the CFA on the frame pointer so the `sub sp, sp, #16` below (and
    // the callbacks' wholesale `mov sp, host_sp`) do not invalidate unwinding
    // through the `bl`s. This mirrors the x86-64 `.cfi_def_cfa rbp, 16`.
    .cfi_def_cfa x29, 96
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]

    // Reserve one 16-byte slot for `thread_ctx`. Every callback reads it back
    // from `[sp]` after restoring the host stack.
    sub sp, sp, #16
    str x0, [sp]

    // Publish the host stack pointer and the top of the guest context.
    mrs x8, tpidr_el0
    mov x9, sp
    str x9, [x8, #{HOST_SP}]
    add x9, x1, #{GUEST_CONTEXT_SIZE}
    str x9, [x8, #{GUEST_CONTEXT_TOP}]

    // Dispatch on the `reenter` flag (in w2).
    cbnz w2, 1f
    bl {init_handler}
    b .Ldone_aarch64
1:
    bl {reenter_handler}
    b .Ldone_aarch64

    // Entered by `BR X16` from the rewriter's shared SVC handler when the
    // guest issues a syscall. State on entry (rewriter ABI, see
    // `litebox_syscall_rewriter::arm64` module docs):
    //
    //   | Item                     | Value                                  |
    //   | ------------------------ | -------------------------------------- |
    //   | x16                      | clobbered (holds the callback address) |
    //   | [sp, #0]                 | saved guest x16                        |
    //   | [sp, #8]                 | guest resume PC (svc_site + 4)         |
    //   | sp                       | guest SP minus 16 (gate frame is live) |
    //   | x0-x15, x17-x30, NZCV    | pristine guest values                  |
    //   | TPIDR_EL0                | host anchor                            |
    .globl syscall_callback
syscall_callback:
    // Clear `in_guest`. This must stay within the first instruction pair:
    // `interrupt_signal_handler` case 1 recognizes this callback by comparing
    // the faulting PC against `syscall_callback`.
    mrs  x16, tpidr_el0
    strb wzr, [x16, #{IN_GUEST}]

    // x16 -> base of the guest `PtRegs`.
    ldr  x16, [x16, #{GUEST_CONTEXT_TOP}]
    sub  x16, x16, #{GUEST_CONTEXT_SIZE}

    // regs[0..=15].
    stp  x0,  x1,  [x16]
    stp  x2,  x3,  [x16, #16]
    stp  x4,  x5,  [x16, #32]
    stp  x6,  x7,  [x16, #48]
    stp  x8,  x9,  [x16, #64]
    stp  x10, x11, [x16, #80]
    stp  x12, x13, [x16, #96]
    stp  x14, x15, [x16, #112]

    // Guest x16 and the resume PC come off the gate frame.
    ldp  x0,  x1,  [sp]
    str  x0,  [x16, #128]         // regs[16] = guest x16
    str  x17, [x16, #136]
    str  x18, [x16, #144]
    // regs[19..=30]. x30 must land here before the `bl` below clobbers it.
    stp  x19, x20, [x16, #152]
    stp  x21, x22, [x16, #168]
    stp  x23, x24, [x16, #184]
    stp  x25, x26, [x16, #200]
    stp  x27, x28, [x16, #216]
    stp  x29, x30, [x16, #232]

    add  x0,  sp,  #16
    str  x0,  [x16, #248]         // sp: undo the gate's 16-byte frame
    str  x1,  [x16, #256]         // pc
    mrs  x0,  nzcv
    str  x0,  [x16, #264]         // pstate
    ldr  x0,  [x16]
    str  x0,  [x16, #272]         // orig_x0
    str  w8,  [x16, #280]         // syscallno
    // regs[0] = -ENOSYS, matching what the kernel leaves in x0 on entry.
    // `mov x0, #-38` assembles to `MOVN X0, #37`, i.e. the 64-bit value
    // 0xFFFF_FFFF_FFFF_FFDA, not a zero-extended 0xFFFF_FFDA.
    mov  x0,  #-38
    str  x0,  [x16]

    // Back onto the host stack, then handle the syscall. This normally jumps
    // back to the guest and only returns when the thread is exiting.
    mrs  x17, tpidr_el0
    ldr  x17, [x17, #{HOST_SP}]
    mov  sp,  x17
    ldr  x0,  [sp]                // thread_ctx
    bl   {syscall_handler}
    b    .Ldone_aarch64

    // Entered from `exception_signal_handler` via `set_signal_return`, which
    // parks the handler arguments in `regs[0..3]` -> x0-x3 on entry here.
    // Exactly as on x86-64, argument 0 is a placeholder that this stub
    // overwrites with `thread_ctx`; arguments 1-3 (trapno, error, cr2) are
    // already in x1-x3 and must not be clobbered. So the only scratch register
    // available is x9 and above.
exception_callback:
    mrs x9, tpidr_el0
    ldr x9, [x9, #{HOST_SP}]
    mov sp, x9
    ldr x0, [sp]                  // thread_ctx
    bl {exception_handler}
    b .Ldone_aarch64

    // Entered either from `interrupt_signal_handler` via `set_signal_return`
    // (all four arguments are placeholders) or by a direct branch from
    // `switch_to_guest` when the `interrupt` byte was already set.
    // `interrupt_handler` takes only `thread_ctx`.
interrupt_callback:
    mrs x9, tpidr_el0
    ldr x9, [x9, #{HOST_SP}]
    mov sp, x9
    ldr x0, [sp]                  // thread_ctx
    bl {interrupt_handler}
    b .Ldone_aarch64

.Ldone_aarch64:
    add sp, sp, #16
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #96
    .cfi_def_cfa sp, 0
    ret
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    HOST_SP = const tls_offset::HOST_SP,
    GUEST_CONTEXT_TOP = const tls_offset::GUEST_CONTEXT_TOP,
    IN_GUEST = const tls_offset::IN_GUEST,
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        "switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt. If
        // so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set the `interrupt` and jump to
        // `interrupt_callback`.
        "mov BYTE PTR fs:in_guest@tpoff, 1",
        "cmp BYTE PTR fs:interrupt@tpoff, 0",
        "jne interrupt_callback",
        // Restore guest context from ctx.
        "mov rsp, rdi",
        // Switch to the guest fsbase
        "mov rdx, fs:guest_fsbase@tpoff",
        "wrfsbase rdx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",           // skip orig_rax
        "pop gs:scratch@tpoff", // read rip into scratch
        "add rsp, 8",           // skip cs
        "popfq",
        "pop rsp",
        "jmp gs:scratch@tpoff", // jump to the guest
        "switch_to_guest_end:",
    );
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be a valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
///
/// # Guest `x16` (IP0) is deliberately not restored
///
/// AArch64 has no memory-indirect branch: there is no `BR [mem]`, so the
/// branch target must first be materialized into a general-purpose register.
/// That register is by definition one that would otherwise hold restored guest
/// state, so restoring all 31 GPRs *and* branching is impossible in a single
/// pass. `x16` is chosen because:
///
/// * `x16`/`x17` (IP0/IP1) are the AAPCS intra-procedure-call scratch
///   registers. A linker-inserted veneer on any long branch may clobber them,
///   so no conforming AArch64 code can rely on their values across a branch.
/// * The rewriter's per-site SVC gate has *already* clobbered `x16` before the
///   callback runs (it spills the guest value to `[SP, #0]` and reuses `x16`
///   to compute the resume address), so the guest value is not live here in
///   the syscall-return path anyway.
///
/// This does deviate from the rewriter's documented contract, which says the
/// callback restores `X16` from `[SP, #0]`.
///
/// TODO: have the rewriter emit a per-site *outbound* stub
/// (`ldr x16, [sp, #0]; add sp, sp, #16; b site+4`) so `x16` is fully
/// restored. That is a pure static branch, so it needs no scratch register and
/// stays host-portable. See
/// `docs/plans/2026-07-29-aarch64-linux-userland-design.md` section 3.
///
/// Note there is no thread-pointer restore here: `TPIDR_EL0` keeps holding the
/// host anchor while the guest runs, and the rewriter redirects guest
/// thread-pointer accesses to `[TPIDR_EL0 + 16]`.
///
/// # The `switch_to_guest_start` / `switch_to_guest_end` bracket
///
/// `interrupt_signal_handler` case 3 tests whether the interrupted PC lies
/// inside this range. The range must span **every** instruction from the
/// `in_guest` store onward, not merely the final few: `mov sp, x16` installs
/// the *guest* stack pointer roughly twenty instructions before `br x16`, and
/// for that entire window neither the host nor the guest register state is
/// self-consistent. `interrupt_callback` is what repairs it, by reloading `SP`
/// from `host_sp`. Do not shrink the bracketed region.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
    "
switch_to_guest_start:
    // Set `in_guest` now, then check for a pending interrupt. If an interrupt
    // arrives after the check, the signal handler sees that the PC is between
    // `switch_to_guest_start` and `switch_to_guest_end` and jumps to
    // `interrupt_callback` itself.
    mrs  x17, tpidr_el0
    mov  w16, #1
    strb w16, [x17, #{IN_GUEST}]
    ldrb w16, [x17, #{INTERRUPT}]
    // The condition is inverted around an unconditional branch on purpose; do
    // not 'simplify' this back to `cbnz w16, interrupt_callback`.
    // `interrupt_callback` lives in `run_thread_arch`'s separate `naked_asm!`
    // block, so the reference is a cross-section relocation resolved by the
    // linker, not by the assembler. A conditional branch emits
    // `R_AARCH64_CONDBR19`, which reaches only +/-1MiB and for which the
    // linker inserts no veneer -- it hard-fails with `relocation truncated to
    // fit` if CGU partitioning or LTO ever places the two functions further
    // apart. `B` emits `R_AARCH64_JUMP26`: +/-128MiB and veneer-able.
    cbz  w16, 3f
    b    interrupt_callback
3:

    // x0 holds `ctx` and stays live until the final two loads.
    ldr  x16, [x0, #264]          // pstate
    msr  nzcv, x16
    ldr  x16, [x0, #248]          // guest sp
    mov  sp, x16
    ldr  x1,  [x0, #8]
    ldp  x2,  x3,  [x0, #16]
    ldp  x4,  x5,  [x0, #32]
    ldp  x6,  x7,  [x0, #48]
    ldp  x8,  x9,  [x0, #64]
    ldp  x10, x11, [x0, #80]
    ldp  x12, x13, [x0, #96]
    ldp  x14, x15, [x0, #112]
    // regs[16] is intentionally skipped; see the doc comment.
    ldr  x17, [x0, #136]
    ldr  x18, [x0, #144]
    ldp  x19, x20, [x0, #152]
    ldp  x21, x22, [x0, #168]
    ldp  x23, x24, [x0, #184]
    ldp  x25, x26, [x0, #200]
    ldp  x27, x28, [x0, #216]
    ldr  x29, [x0, #232]
    ldr  x30, [x0, #240]
    ldr  x16, [x0, #256]          // guest PC -- x16 is the branch register
    ldr  x0,  [x0, #0]            // guest x0, last use of ctx
    br   x16
switch_to_guest_end:
"
    ,
    IN_GUEST = const tls_offset::IN_GUEST,
    INTERRUPT = const tls_offset::INTERRUPT,
    );
}

/// Non-guest threads (e.g., network workers, background tasks) should call this
/// function at the start of their execution so the kernel only delivers
/// `SIGALRM` / `SIGINT` to guest threads, which have the proper signal-handler
/// context to re-enter the shim.
fn block_guest_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGALRM);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
    }
}

/// Spawn a non-guest ("host") thread that automatically blocks guest interrupt
/// signals before running `f`.
///
/// Every background thread created by a runner (network workers, I/O helpers,
/// etc.) should use this function instead of [`std::thread::spawn`] to ensure
/// that `SIGALRM` and `SIGINT` are only delivered to guest threads.
///
/// # Example
///
/// ```ignore
/// let handle = litebox_platform_linux_userland::spawn_host_thread(move || {
///     // This thread will never receive SIGALRM or SIGINT.
///     do_background_work();
/// });
/// ```
pub fn spawn_host_thread<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        block_guest_signals();
        f()
    })
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
    >,
    mut ctx: litebox_common_linux::PtRegs,
) {
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx, false);
    // TODO: have syscall_callback return if we need to terminate the process.
    // We should return this value to the caller so load_program can return it
    // to the user.
}

// A handle to a platform thread.
#[derive(Clone)]
pub struct ThreadHandle(std::sync::Arc<std::sync::Mutex<Option<libc::pthread_t>>>);

thread_local! {
    static CURRENT_THREAD: std::cell::RefCell<Option<ThreadHandle>> = const { std::cell::RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f`, ensuring that [`ThreadHandle::current`] can be called within `f`.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        let handle = ThreadHandle(std::sync::Arc::new(std::sync::Mutex::new(Some(unsafe {
            libc::pthread_self()
        }))));
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested with_thread_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD.take().unwrap();
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    /// Returns the current thread handle.
    fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    /// Interrupts the thread, delivering a signal to it.
    fn interrupt(&self) {
        let thread = self.0.lock().unwrap();
        if let Some(&thread) = thread.as_ref() {
            unsafe {
                libc::pthread_kill(thread, INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed));
            }
        }
    }
}

impl litebox::platform::ThreadProvider for LinuxUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new().spawn(move || thread_start(init_thread, ctx))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        // Sets `gsbase = fsbase` (x86_64) or `fs = gs` (x86) on the current thread
        // to mirror the TLS base used in guest context, so that test threads can use the
        // same TLS access code as guest threads.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "rdfsbase {tmp}",
                "wrgsbase {tmp}",
                tmp = out(reg) _,
                options(nostack, preserves_flags),
            );
        }

        // AArch64 needs no thread-pointer mirroring: there is no second
        // thread-pointer register, and `TPIDR_EL0` already holds the host
        // anchor on every thread. What the x86-64 mirroring *also* achieves,
        // incidentally, is making a test thread pass the `gsbase != 0`
        // guest-thread probe in `interrupt_signal_handler`. That part does
        // need an explicit equivalent, or test threads would re-raise
        // process-wide instead of recording pending signals locally, diverging
        // from x86-64 behaviour.
        #[cfg(target_arch = "aarch64")]
        let was_guest_thread = is_guest_thread();
        #[cfg(target_arch = "aarch64")]
        set_is_guest_thread(true);
        #[cfg(target_arch = "aarch64")]
        let _guest_thread_guard = litebox::utils::defer(|| set_is_guest_thread(was_guest_thread));

        ThreadHandle::run_with_handle(f)
    }
}

impl litebox::platform::TimerProvider for LinuxUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        // Create a POSIX per-process timer.  We always deliver via SIGALRM at
        // the kernel level (whose handler is already registered) and encode the
        // *desired* guest signal in `sigev_value.sival_int`.  The signal handler
        // reads `si_value` when `si_code == SI_TIMER` to determine which guest
        // signal to record.
        let mut sev: libc::sigevent = unsafe { core::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_SIGNAL;
        sev.sigev_signo = libc::SIGALRM;
        sev.sigev_value.sival_ptr = signal.as_i32() as *mut libc::c_void;

        let mut timer_id: libc::timer_t = std::ptr::null_mut();
        let ret =
            unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &raw mut sev, &raw mut timer_id) };
        assert!(
            ret == 0,
            "timer_create failed: {}",
            std::io::Error::last_os_error()
        );

        Ok(TimerHandle(timer_id))
    }
}

/// A timer handle backed by POSIX `timer_create` / `timer_settime`.
///
/// Each handle owns an independent kernel timer, so multiple timers can
/// coexist without interfering with each other.
pub struct TimerHandle(libc::timer_t);

// Safety: `timer_t` is an opaque kernel handle safe to send across threads.
unsafe impl Send for TimerHandle {}
unsafe impl Sync for TimerHandle {}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        // Safety: we own the timer and it will not be used after drop.
        unsafe {
            libc::timer_delete(self.0);
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: core::time::Duration) {
        let its = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs().cast_signed().trunc(),
                tv_nsec: duration.subsec_nanos().cast_signed().into(),
            },
        };
        // Safety: valid timer id and itimerspec.
        let ret = unsafe { libc::timer_settime(self.0, 0, &raw const its, std::ptr::null_mut()) };
        assert!(
            ret == 0,
            "timer_settime failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

impl litebox::platform::RawMutexProvider for LinuxUserland {
    type RawMutex = RawMutex;

    fn update_waker(&self, waker: Option<litebox::event::wait::Waker<Self>>)
    where
        Self: litebox::sync::RawSyncPrimitivesProvider,
    {
        let mut waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                concat!("xchg ", tls!("wait_waker_addr"), ", {}"),
                inout(reg) waker_ptr,
                options(nostack),
            );
        }
        // Same sequentially-consistent `ldaxr`/`stlxr` exchange as
        // `take_pending_host_signals`, on a 64-bit slot. The interrupt signal
        // handler reads this slot, so the ordering must match the x86-64
        // `xchg` it replaces.
        #[cfg(target_arch = "aarch64")]
        // SAFETY: exchanges a naturally aligned `u64` in this thread's own TLS
        // control block, whose offset from `TPIDR_EL0` is checked by
        // `assert_tls_layout`.
        unsafe {
            let new_ptr = waker_ptr;
            core::arch::asm!(
                "mrs {addr}, tpidr_el0",
                "add {addr}, {addr}, #{off}",
                "2:",
                "ldaxr {old}, [{addr}]",
                "stlxr {status:w}, {new}, [{addr}]",
                "cbnz {status:w}, 2b",
                addr = out(reg) _,
                old = out(reg) waker_ptr,
                new = in(reg) new_ptr,
                status = out(reg) _,
                off = const tls_offset::WAIT_WAKER_ADDR,
                options(nostack),
            );
        }
        if !waker_ptr.is_null() {
            // SAFETY: old waker_ptr was created by Box::into_raw in a previous call to update_waker.
            unsafe { drop(Box::from_raw(waker_ptr)) };
        }
    }
}

pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
}

impl RawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
        }
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // We wait on the futex, with a timeout if needed
        match futex_timeout(
            &self.inner,
            FutexOperation::Wait,
            /* expected value */ val,
            timeout,
            /* ignored */ None,
        ) {
            Ok(0) | Err(syscalls::Errno::EINTR) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(syscalls::Errno::EAGAIN) => Err(ImmediatelyWokenUp),
            Err(syscalls::Errno::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            Err(e) => {
                panic!("Unexpected errno={e} for FUTEX_WAIT")
            }
            _ => unreachable!(),
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();

        futex_val2(
            &self.inner,
            FutexOperation::Wake,
            /* number to wake up */ n,
            /* val2: ignored */ 0,
            /* uaddr2: ignored */ None,
        )
        .expect("failed to wake up waiters")
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl litebox::platform::IPInterfaceProvider for LinuxUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        match unsafe {
            syscalls::syscall3(
                syscalls::Sysno::write,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_ptr() as usize,
                packet.len(),
            )
        } {
            Ok(n) => {
                if n != packet.len() {
                    unimplemented!("unexpected size {n}")
                }
                Ok(())
            }
            Err(errno) => {
                unimplemented!("unexpected error {errno}")
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::read,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_mut_ptr() as usize,
                packet.len(),
            )
        }
        .map_err(|errno| match errno {
            #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
            syscalls::Errno::EWOULDBLOCK | syscalls::Errno::EAGAIN => {
                litebox::platform::ReceiveError::WouldBlock
            }
            _ => unimplemented!("unexpected error {errno}"),
        })
    }
}

impl litebox::platform::TimeProvider for LinuxUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            #[cfg_attr(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                expect(clippy::useless_conversion)
            )]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().trunc(),
            ),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[cfg_attr(
                any(target_arch = "x86_64", target_arch = "aarch64"),
                expect(clippy::useless_conversion)
            )]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().trunc(),
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    inner: Duration,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.inner.checked_sub(earlier.inner)
    }
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        Some(Self {
            inner: self.inner.checked_add(duration)?,
        })
    }
}

pub struct SystemTime {
    inner: Duration,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: Duration::ZERO,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

#[cfg(target_arch = "x86_64")]
impl litebox::platform::ArchSpecificProvider for LinuxUserland {
    // We swap gs and fs before and after a syscall, so while handling a guest
    // syscall the guest's fs base is stored in the gs base register; the
    // per-thread `guest_fsbase` slot holds the value that will be programmed
    // into fs base on guest re-entry.
    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::FsBase => {
                if litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    set_guest_fsbase(val);
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            litebox::platform::ArchSpecificRegister::GsBase => {
                // GS base is used internally by this platform to hold the host
                // TLS base across the guest/host fs-gs swap, so it is not
                // directly programmable by the guest.
                Err(litebox::platform::ArchSpecificError::RegisterReserved)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::FsBase => Ok(get_guest_fsbase()),
            litebox::platform::ArchSpecificRegister::GsBase => {
                // See note above: gs base is reserved for host TLS on this
                // platform and is not exposed to the guest.
                Err(litebox::platform::ArchSpecificError::RegisterReserved)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl litebox::platform::ArchSpecificProvider for LinuxUserland {
    // Hardware `TPIDR_EL0` holds the *host* thread pointer for this thread's
    // entire lifetime, including while guest code executes. The guest's own
    // thread pointer lives in the runtime-owned `guest_tpidr` slot, which the
    // syscall rewriter redirects every guest `MSR`/`MRS TPIDR_EL0` to. So the
    // guest thread pointer is read and written purely as memory here; the
    // system register is never touched.
    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => {
                if litebox_common_linux::arch::is_valid_user_tls_base(val) {
                    set_guest_tpidr(val);
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => Ok(get_guest_tpidr()),
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
impl litebox::platform::RawPointerProvider for LinuxUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

/// Operations currently supported by the safer variants of the Linux futex syscall
/// ([`futex_timeout`] and [`futex_val2`]).
#[repr(i32)]
enum FutexOperation {
    Wait = litebox_common_linux::FUTEX_WAIT,
    Wake = litebox_common_linux::FUTEX_WAKE,
}

/// Safer invocation of the Linux futex syscall, with the "timeout" variant of the arguments.
#[expect(clippy::similar_names, reason = "sec/nsec are as needed by libc")]
fn futex_timeout(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    timeout: Option<Duration>,
    uaddr2: Option<&AtomicU32>,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = std::ptr::from_ref(uaddr);
    let futex_op: i32 = futex_op as _;
    let timeout = timeout.map(|t| {
        const TEN_POWER_NINE: u128 = 1_000_000_000;
        let nanos: u128 = t.as_nanos();
        let tv_sec = nanos
            .checked_div(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        let tv_nsec = nanos
            .checked_rem(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        litebox_common_linux::Timespec { tv_sec, tv_nsec }
    });
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                {
                    syscalls::Sysno::futex
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            if let Some(t) = timeout.as_ref() {
                core::ptr::from_ref(t) as usize
            } else {
                0 // No timeout
            },
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            0,
        )
    }
}

/// Safer invocation of the Linux futex syscall, with the "val2" variant of the arguments.
fn futex_val2(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    val2: u32,
    uaddr2: Option<&AtomicU32>,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = std::ptr::from_ref(uaddr);
    let futex_op: i32 = futex_op as _;
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                {
                    syscalls::Sysno::futex
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            val2 as usize,
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            0,
        )
    }
}

fn prot_flags(flags: MemoryRegionPermissions) -> ProtFlags {
    let mut res = ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    /// 48-bit user virtual address space.
    #[cfg(target_arch = "aarch64")]
    const TASK_ADDR_MAX: usize = 0x0000_FFFF_FFFF_F000; // (1 << 48) - PAGE_SIZE;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | match fixed_address_behavior {
                FixedAddressBehavior::Hint => MapFlags::empty(),
                FixedAddressBehavior::Replace => MapFlags::MAP_FIXED,
                FixedAddressBehavior::NoReplace => MapFlags::MAP_FIXED_NOREPLACE,
            }
            | if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            }
            | if populate_pages_immediately {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            };
        let r = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                    {
                        syscalls::Sysno::mmap
                    }
                },
                suggested_range.start,
                suggested_range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                usize::MAX,
                0,
            )
        };
        let ptr = r.map_err(|err| match err {
            syscalls::Errno::ENOMEM => litebox::platform::page_mgmt::AllocationError::OutOfMemory,
            syscalls::Errno::EEXIST => {
                assert!(matches!(
                    fixed_address_behavior,
                    FixedAddressBehavior::NoReplace
                ));
                litebox::platform::page_mgmt::AllocationError::AddressInUse
            }
            _ => panic!("unhandled mmap error {err}"),
        })?;
        Ok(UserMutPtr::from_usize(ptr))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe { syscalls::syscall2(syscalls::Sysno::munmap, range.start, range.len()) }
            .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        let res = unsafe {
            syscalls::syscall5(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                MRemapFlags::MREMAP_MAYMOVE.bits() as usize,
                new_range.start,
            )
            .expect("mremap failed")
        };
        Ok(UserMutPtr::from_usize(res))
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }

    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }

        let file_path_cstr =
            std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // TODO(jb): We should likely be storing pre-opened FDs, right?
        let fd = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                AT_FDCWD,
                file_path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let fd = fd.expect("file should remain unchanged on host");

        let mut flags = MapFlags::MAP_PRIVATE;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {}
            FixedAddressBehavior::Replace => flags |= MapFlags::MAP_FIXED,
            FixedAddressBehavior::NoReplace => flags |= MapFlags::MAP_FIXED_NOREPLACE,
        }

        let result = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                    {
                        syscalls::Sysno::mmap
                    }
                },
                suggested_start,
                source_data.len(),
                prot_flags(permissions).bits().reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                fd,
                {
                    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                    {
                        file_offset
                    }
                },
            )
        };

        let _ = unsafe { syscalls::syscall1(syscalls::Sysno::close, fd) };

        match result {
            Ok(ptr) => Ok(UserMutPtr::from_usize(ptr)),
            Err(_) => Err(CowAllocationError::InternalFailure),
        }
    }
}

impl litebox::platform::StdioProvider for LinuxUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::read,
                usize::try_from(litebox_common_linux::STDIN_FILENO).unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
            )
        }
        .map_err(|err| match err {
            syscalls::Errno::EPIPE => litebox::platform::StdioReadError::Closed,
            _ => panic!("unhandled error {err}"),
        })
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::write,
                usize::try_from(match stream {
                    litebox::platform::StdioOutStream::Stdout => {
                        litebox_common_linux::STDOUT_FILENO
                    }
                    litebox::platform::StdioOutStream::Stderr => {
                        litebox_common_linux::STDERR_FILENO
                    }
                })
                .unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
            )
        }
        .map_err(|err| match err {
            syscalls::Errno::EPIPE => litebox::platform::StdioWriteError::Closed,
            _ => panic!("unhandled error {err}"),
        })
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        self.stdio_is_tty[stream as usize]
    }
}

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback();
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

unsafe extern "C-unwind" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx));
}

/// Handles Linux syscalls and dispatches them to LiteBox implementations.
///
/// Returns only if the guest thread is exiting. Otherwise, resumes the guest
/// without returning.
///
/// # Safety
///
/// - The `ctx` pointer must be valid pointer to a `litebox_common_linux::PtRegs` structure.
/// - If any syscall argument is a pointer, it must be valid.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development
/// purposes.
#[allow(clippy::cast_sign_loss)]
unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx));
}

extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext,
    trapno: usize,
    error: usize,
    cr2: usize,
) {
    #[cfg(target_arch = "x86_64")]
    let info = litebox::shim::ExceptionInfo {
        exception: litebox::shim::Exception(trapno.try_into().unwrap()),
        error_code: error.try_into().unwrap(),
        cr2,
        kernel_mode: false,
    };
    // On AArch64 the hardware trap number and error code are not visible to
    // userspace, so `exception_signal_handler` passes the signal number in
    // `trapno` and zero in `error`, and the exception class is recovered from
    // the signal.
    #[cfg(target_arch = "aarch64")]
    let info = {
        let _ = error;
        let exception = match i32::try_from(trapno).unwrap_or(0) {
            libc::SIGILL => litebox::shim::Exception::INSTRUCTION_ABORT_LOWER_EL,
            libc::SIGTRAP => litebox::shim::Exception::BRK64,
            // Everything else reaching this handler -- SIGSEGV, SIGBUS, and
            // SIGFPE, which has no ESR exception class of its own -- is
            // reported as a data abort. That describes an unexpected memory
            // fault more truthfully than a fabricated class would.
            _ => litebox::shim::Exception::DATA_ABORT_LOWER_EL,
        };
        litebox::shim::ExceptionInfo {
            exception,
            fault_address: cr2,
            // The real ESR_EL1 is not exposed to userspace — the arm64 signal
            // frame carries no syndrome register — so synthesize one holding
            // just the exception class in bits 31:26. The instruction-specific
            // syndrome (ISS) bits 24:0 are unavoidably zero.
            esr: u64::from(exception.0) << 26,
            kernel_mode: false,
        }
    };
    thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info));
}

extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.interrupt(ctx));
}

/// Calls `f` in order to call into a shim entrypoint.
impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                concat!("mov BYTE PTR ", tls!("interrupt"), ", 0"),
                options(nostack, preserves_flags)
            );
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: writes a single byte in this thread's own TLS control block.
        unsafe {
            core::arch::asm!(
                "mrs {tmp}, tpidr_el0",
                "strb wzr, [{tmp}, #{off}]",
                tmp = out(reg) _,
                off = const tls_offset::INTERRUPT,
                options(nostack, preserves_flags)
            );
        }
        let op = f(self.shim, self.ctx);
        match op {
            ContinueOperation::Resume => unsafe { switch_to_guest(self.ctx) },
            ContinueOperation::Terminate => {}
        }
    }
}

impl litebox::platform::SystemInfoProvider for LinuxUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // Enabling VDSO on x86 causes glibc to not set a restorer in signal
        // handlers, which we do not currently support. Disable VDSO for
        // now.
        //
        // TODO: implement VDSO in the shim, don't try to pass through the
        // platform VDSO.
        None
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

/// LinuxUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for LinuxUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }
}

static mut NEXT_SA: [libc::sigaction; 64] = unsafe { core::mem::zeroed() };
static INTERRUPT_SIGNAL_NUMBER: AtomicI32 = AtomicI32::new(0);

fn register_exception_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        fn sigaction(sig: i32, sa: Option<&libc::sigaction>, old_sa: &mut libc::sigaction) {
            unsafe {
                let r = libc::sigaction(
                    sig,
                    sa.map_or(std::ptr::null(), |sa| &raw const *sa),
                    &raw mut *old_sa,
                );
                assert!(
                    r >= 0,
                    "failed to query existing signal handler for signal {}: {}",
                    sig,
                    std::io::Error::last_os_error()
                );
            }
        }

        let interrupt_signal = {
            // Find an RT signal number for interrupt handling.
            let sig = (libc::SIGRTMIN()..=libc::SIGRTMAX())
                .find(|&i| {
                    let mut old_sa = unsafe { core::mem::zeroed() };
                    sigaction(i, None, &mut old_sa);
                    old_sa.sa_sigaction == libc::SIG_DFL
                })
                .expect("no available real-time signal for interrupt handling");

            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction(sig, Some(&sa), &mut old_sa);
            assert_eq!(
                old_sa.sa_sigaction,
                libc::SIG_DFL,
                "signal {sig} handler already installed",
            );
            INTERRUPT_SIGNAL_NUMBER.store(sig, Ordering::Relaxed);
            sig
        };

        let exception_signals = &[
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGTRAP,
            // We'd like to log forbidden syscalls in debug mode
            #[cfg(debug_assertions)]
            libc::SIGSYS,
        ];
        for &sig in exception_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = exception_signal_handler as *const () as usize;
                // Block the interrupt signal while handling exceptions to avoid
                // saving the exception signal handler state as guest state.
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                // Note: the handler could start running before this call even
                // returns, so pass `&mut NEXT_SA` directly.
                sigaction(
                    sig,
                    Some(&sa),
                    &mut NEXT_SA[sig.reinterpret_as_unsigned() as usize],
                );
            }
        }

        // Note that non-guest threads should block these signals, so it always fires on a guest thread.
        let traditional_signals = &[libc::SIGINT, libc::SIGALRM];
        for &sig in traditional_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
                // Block the interrupt signal while handling signals
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                let mut old_sa = core::mem::zeroed();
                sigaction(sig, Some(&sa), &mut old_sa);
                assert_eq!(
                    old_sa.sa_sigaction,
                    libc::SIG_DFL,
                    "signal {sig} handler already installed",
                );
            }
        }
    });
}

/// Runs `f` with an alternate signal stack set up.
fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let alt_stack_size = libc::SIGSTKSZ * 2;
    let guard_page_size = 0x1000;
    let stack_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            guard_page_size + alt_stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(
        stack_base != libc::MAP_FAILED,
        "failed to allocate memory for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _unmap_guard = litebox::utils::defer(|| {
        let r = unsafe { libc::munmap(stack_base, guard_page_size + alt_stack_size) };
        assert!(
            r == 0,
            "failed to free memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    // Set up a guard page to catch stack overflows.
    let r = unsafe { libc::mprotect(stack_base, guard_page_size, libc::PROT_NONE) };
    assert!(
        r == 0,
        "failed to set guard page for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    let alt_stack = libc::stack_t {
        ss_sp: stack_base.cast(),
        ss_flags: 0,
        ss_size: alt_stack_size,
    };
    let mut oss = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    unsafe {
        let r = libc::sigaltstack(&raw const alt_stack, &raw mut oss);
        assert!(
            r >= 0,
            "failed to set up alternate signal stack: {}",
            std::io::Error::last_os_error(),
        );
    }
    let _restore_guard = litebox::utils::defer(|| unsafe {
        let r = libc::sigaltstack(&raw const oss, std::ptr::null_mut());
        assert!(
            r >= 0,
            "failed to restore original signal stack: {}",
            std::io::Error::last_os_error()
        );
    });
    f()
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Restores the proper host `fsbase` so that TLS can be used. Clears `in_guest`
/// and optionally sets `interrupt`. If `in_guest` was previously set, returns
/// the guest context pointer (which does not necessarily have up-to-date guest
/// register state yet).
#[cfg(target_arch = "x86_64")]
fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    unsafe {
        let gsbase: u64;
        core::arch::asm! {
            "rdgsbase {}", out(reg) gsbase
        };
        let is_in_guest = if gsbase == 0 {
            false
        } else {
            let in_guest: u8;
            core::arch::asm! {
                "mov {in_guest}, BYTE PTR gs:in_guest@tpoff",
                "mov BYTE PTR gs:in_guest@tpoff, 0",
                in_guest = out(reg_byte) in_guest,
                options(nostack, preserves_flags)
            }
            if set_interrupt {
                core::arch::asm! {
                    "mov BYTE PTR gs:interrupt@tpoff, 1",
                    options(nostack, preserves_flags)
                };
            }
            in_guest != 0
        };
        if !is_in_guest {
            return None;
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "wrfsbase {gsbase}",
            "mov {guest_context_top}, fs:guest_context_top@tpoff",
            gsbase = in(reg) gsbase,
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        Some(guest_context_top.sub(1))
    }
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
#[cfg(target_arch = "x86_64")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let litebox_common_linux::PtRegs {
        r15,
        r14,
        r13,
        r12,
        rbp,
        rbx,
        r11,
        r10,
        r9,
        r8,
        rax,
        rcx,
        rdx,
        rsi,
        rdi,
        orig_rax,
        rip,
        cs: _,
        eflags,
        rsp,
        ss: _,
    } = regs;
    for (reg, sig_reg) in [
        (r15, libc::REG_R15),
        (r14, libc::REG_R14),
        (r13, libc::REG_R13),
        (r12, libc::REG_R12),
        (rbp, libc::REG_RBP),
        (rbx, libc::REG_RBX),
        (r11, libc::REG_R11),
        (r10, libc::REG_R10),
        (r9, libc::REG_R9),
        (r8, libc::REG_R8),
        (rax, libc::REG_RAX),
        (rcx, libc::REG_RCX),
        (rdx, libc::REG_RDX),
        (rsi, libc::REG_RSI),
        (rdi, libc::REG_RDI),
        (rip, libc::REG_RIP),
        (rsp, libc::REG_RSP),
        (eflags, libc::REG_EFL),
    ] {
        *reg = context.uc_mcontext.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned()
            .trunc();
    }
    *orig_rax = *rax;
}

/// Updates a Linux signal context to return to `f` with the given arguments.
#[cfg(target_arch = "x86_64")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = &mut context.uc_mcontext;
    sigctx.gregs[libc::REG_RIP as usize] = (f as usize).reinterpret_as_signed() as i64;
    sigctx.gregs[libc::REG_RDI as usize] = p0 as i64;
    sigctx.gregs[libc::REG_RSI as usize] = p1 as i64;
    sigctx.gregs[libc::REG_RDX as usize] = p2 as i64;
    sigctx.gregs[libc::REG_RCX as usize] = p3 as i64;
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Clears `in_guest` and optionally sets `interrupt`. If `in_guest` was
/// previously set, returns the guest context pointer (which does not
/// necessarily have up-to-date guest register state yet).
///
/// Unlike the x86-64 counterpart there is no host-TLS recovery step:
/// `TPIDR_EL0` holds the host anchor at all times, including throughout guest
/// execution, so ordinary TLS addressing already works on entry.
#[cfg(target_arch = "aarch64")]
fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    let tp: usize;
    // SAFETY: reads the host thread pointer. `TPIDR_EL0` is never repointed at
    // a guest value — the rewriter redirects guest thread-pointer accesses to
    // the `guest_tpidr` slot instead — so it is the host anchor here even if
    // this signal interrupted guest code.
    unsafe {
        core::arch::asm!(
            "mrs {}, tpidr_el0",
            out(reg) tp,
            options(nostack, nomem, preserves_flags)
        );
    }
    // SAFETY: `tp` addresses this thread's own TLS control block. Every offset
    // used below is checked against the link-time layout by
    // `assert_tls_layout`, and each access is naturally aligned and in bounds
    // of that block. Volatile because these slots are also written by the
    // transition assembly, which the compiler cannot see.
    unsafe {
        let in_guest = (tp + tls_offset::IN_GUEST) as *mut u8;
        let was_in_guest = in_guest.read_volatile();
        in_guest.write_volatile(0);
        if set_interrupt {
            ((tp + tls_offset::INTERRUPT) as *mut u8).write_volatile(1);
        }
        if was_in_guest == 0 {
            return None;
        }
        // `guest_context_top` points one past the end of the guest `PtRegs`,
        // as published by `run_thread_arch`; step back one to get its base.
        let top = ((tp + tls_offset::GUEST_CONTEXT_TOP) as *const usize).read_volatile();
        Some((top as *mut litebox_common_linux::PtRegs).sub(1))
    }
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
#[cfg(target_arch = "aarch64")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let m = &context.uc_mcontext;
    // Zip rather than index, so a length mismatch between `PtRegs::regs` and
    // `mcontext_t::regs` truncates instead of panicking or reading past an end.
    for (dst, src) in regs.regs.iter_mut().zip(m.regs.iter()) {
        *dst = (*src).trunc();
    }
    regs.sp = m.sp.trunc();
    regs.pc = m.pc.trunc();
    regs.pstate = m.pstate;
    // This `PtRegs` slot is reused across guest entries, so `syscallno` may
    // still hold a syscall number written by `syscall_callback` on an earlier
    // trip through the guest. Leaving it would tell the shim a syscall is in
    // flight during what is actually an exception or an interrupt. Follow the
    // arm64 kernel and mark "not in a syscall" explicitly.
    //
    // Note x86-64's `copy_signal_context` deliberately differs: it sets
    // `orig_rax = rax` and has no `syscallno` field to invalidate.
    regs.orig_x0 = regs.regs[0];
    regs.syscallno = NO_SYSCALL;
}

/// The arm64 kernel's `syscallno` sentinel for "this context is not in a
/// syscall" (`NO_SYSCALL` in `arch/arm64/include/asm/ptrace.h`).
#[cfg(target_arch = "aarch64")]
const NO_SYSCALL: i32 = -1;

/// Widens a host-pointer-sized value into an AArch64 general-purpose register
/// slot in `mcontext_t`.
///
/// AArch64 is always 64-bit, so this never fails; it exists so the conversion
/// reads as a widening rather than a lossy `as` cast.
#[cfg(target_arch = "aarch64")]
fn to_greg(value: usize) -> u64 {
    u64::try_from(value).expect("aarch64 pointers are 64-bit")
}

/// Updates a Linux signal context to return to `f` with the given arguments.
#[cfg(target_arch = "aarch64")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let m = &mut context.uc_mcontext;
    m.pc = to_greg(f as usize);
    // AAPCS64: first four integer arguments in x0-x3.
    m.regs[0] = to_greg(p0.reinterpret_as_unsigned());
    m.regs[1] = to_greg(p1.reinterpret_as_unsigned());
    m.regs[2] = to_greg(p2.reinterpret_as_unsigned());
    m.regs[3] = to_greg(p3.reinterpret_as_unsigned());
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // Return an error code for the syscall and log it in debug mode.
    //
    // Gated to x86-64 rather than ported: the only producer of SIGSYS here is
    // the seccomp filter installed by `enable_seccomp_filter`, which is itself
    // `#[cfg(target_arch = "x86_64")]`. On AArch64 no SIGSYS this runtime
    // caused can reach here, so decoding one would be dead code.
    #[cfg(all(debug_assertions, target_arch = "x86_64"))]
    if signum == libc::SIGSYS {
        use core::fmt::Write as _;
        #[cfg(target_arch = "x86_64")]
        let eax_idx = libc::REG_RAX as usize;
        let sysno = context.uc_mcontext.gregs[eax_idx];
        context.uc_mcontext.gregs[eax_idx] = i64::from(-libc::EINVAL);
        // Signal-safe: format on the stack via arrayvec (no heap allocation).
        let mut buf = arrayvec::ArrayString::<320>::new();
        if sysno == libc::SYS_openat {
            #[cfg(target_arch = "x86_64")]
            let rsi = context.uc_mcontext.gregs[libc::REG_RSI as usize] as *const i8;
            let c_path = unsafe { core::ffi::CStr::from_ptr(rsi) };
            // libc may call `openat` for certain files that we can ignore, e.g., /proc/sys/vm/overcommit_memory.
            // Log the paths in case we need to allow some of them in the future.
            let _ = writeln!(buf, "INFO: openat with {c_path:?} is not allowed");
        } else {
            let _ = writeln!(buf, "WARNING: disallowed syscall invoked: {sysno}");
        }
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::write,
                libc::STDERR_FILENO as usize,
                buf.as_ptr() as usize,
                buf.len(),
            )
        };
        return;
    }

    let Some(regs) = signal_handler_exit_guest(context, false) else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    copy_signal_context(unsafe { &mut *regs }, context);

    // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
    let _ = run_thread_arch as *const () as usize;

    // Jump to exception_callback.
    let sigctx = &context.uc_mcontext;
    #[cfg(target_arch = "x86_64")]
    let (trapno, err, cr2) = (
        sigctx.gregs[libc::REG_TRAPNO as usize].trunc(),
        sigctx.gregs[libc::REG_ERR as usize].trunc(),
        sigctx.gregs[libc::REG_CR2 as usize].trunc(),
    );
    // AArch64 exposes no trap number or error code to userspace, so the signal
    // number stands in for the trap and the error code is always zero;
    // `exception_handler` recovers an exception class from it. The four-argument
    // shape is kept so `exception_callback`'s x1/x2/x3 marshalling is shared.
    //
    // The fault address comes from `uc_mcontext.fault_address`, not
    // `siginfo.si_addr`. That field is what the arm64 kernel copies out of
    // `current->thread.fault_address`, i.e. FAR_EL1 — exactly what
    // `ExceptionInfo::fault_address` is documented to carry. `si_addr` is a
    // per-signal derived value and for SIGILL is the faulting *PC*, which
    // would put a program counter in a field named `fault_address`.
    #[cfg(target_arch = "aarch64")]
    let (trapno, err, cr2) = (
        isize::try_from(signum).expect("signal numbers are small"),
        0isize,
        TruncateExt::<usize>::trunc(sigctx.fault_address).reinterpret_as_signed(),
    );
    set_signal_return(context, exception_callback, 0, trapno, err, cr2);
}

/// Runs the next signal handler in the chain.
unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    if signum == libc::SIGSEGV {
        let ip: usize = {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize]
                    .reinterpret_as_unsigned()
                    .trunc()
            }
            #[cfg(target_arch = "aarch64")]
            {
                context.uc_mcontext.pc.trunc()
            }
        };
        if let Some(fixup_addr) = litebox::mm::exception_table::search_exception_tables(ip) {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize] =
                    fixup_addr.reinterpret_as_signed() as i64;
            }
            #[cfg(target_arch = "aarch64")]
            {
                context.uc_mcontext.pc = to_greg(fixup_addr);
            }
            return;
        }
    }

    unsafe {
        let next_sa = &NEXT_SA[signum.reinterpret_as_unsigned() as usize];
        match next_sa.sa_sigaction {
            libc::SIG_DFL => {
                // Block this signal and raise.
                let mut set: libc::sigset_t = core::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, signum);
                libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
                libc::raise(signum);
                unreachable!()
            }
            libc::SIG_IGN => {}
            _ => {
                // Call the next handler
                if next_sa.sa_flags & libc::SA_SIGINFO == 0 {
                    let handler: extern "C" fn(libc::c_int) =
                        core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum);
                } else {
                    let handler: extern "C" fn(
                        libc::c_int,
                        *mut libc::siginfo_t,
                        *mut libc::ucontext_t,
                    ) = core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum, info, context);
                }
            }
        }
    }
}

/// Records a pending host signal in the TLS bitmask and wakes any condvar the
/// thread is blocked on.
///
/// # Safety
///
/// Must be called from a signal handler on a guest thread.
///
/// On x86-64 that additionally requires the thread's saved host TLS segment
/// register (`gsbase`) to be valid, since the bitmask is reached through it.
/// On AArch64 there is no such precondition to check: `TPIDR_EL0` holds the
/// host anchor on every thread at all times, so the TLS control block is
/// always addressable.
unsafe fn record_pending_signal(signal: litebox_common_linux::signal::Signal) {
    let mask: u32 = 1u32 << (signal.as_i32() - 1);
    #[cfg(target_arch = "x86_64")]
    let waker_addr: usize;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            concat!("lock or DWORD PTR ", saved_tls!("pending_host_signals"), ", {mask:e}"),
            mask = in(reg) mask,
            options(nostack)
        );
        core::arch::asm!(
            concat!("mov {}, ", saved_tls!("wait_waker_addr")),
            out(reg) waker_addr,
            options(nostack, preserves_flags)
        );
    }

    // An `ldxr`/`stxr` retry loop rather than the LSE `stset`: `stset` is
    // ARMv8.1-A, while the `aarch64-unknown-linux-gnu` baseline is ARMv8.0-A,
    // so using it would need `+lse` and would raise this crate's hardware
    // floor. The acquire/release pairing gives the same sequentially
    // consistent ordering as the x86-64 `lock or`.
    #[cfg(target_arch = "aarch64")]
    let waker_addr: usize;
    #[cfg(target_arch = "aarch64")]
    // SAFETY: both slots are in this thread's own TLS control block at offsets
    // checked by `assert_tls_layout`, and both accesses are naturally aligned.
    // The exclusive monitor reservation is opened and closed within the loop.
    unsafe {
        core::arch::asm!(
            "mrs {tp}, tpidr_el0",
            "add {addr}, {tp}, #{pending_off}",
            "2:",
            "ldaxr {old:w}, [{addr}]",
            "orr {new:w}, {old:w}, {mask:w}",
            "stlxr {status:w}, {new:w}, [{addr}]",
            "cbnz {status:w}, 2b",
            "ldr {waker}, [{tp}, #{waker_off}]",
            tp = out(reg) _,
            addr = out(reg) _,
            old = out(reg) _,
            new = out(reg) _,
            status = out(reg) _,
            waker = out(reg) waker_addr,
            mask = in(reg) mask,
            pending_off = const tls_offset::PENDING_HOST_SIGNALS,
            waker_off = const tls_offset::WAIT_WAKER_ADDR,
            options(nostack)
        );
    }

    if waker_addr == 0 {
        return;
    }
    // SAFETY: if `waker_addr` is not zero, that means the current thread is suspended
    // to handle this signal and it points to a valid Waker whose lifetime spans the
    // entire interruptible wait, set by [`RawMutexProvider::update_waker`].
    let waker = unsafe { &*(waker_addr as *const litebox::event::wait::Waker<LinuxUserland>) };
    waker.wake();
}

/// Signal handler for interrupt signals.
unsafe fn interrupt_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    #[cfg(debug_assertions)]
    let raise_signal = |signum: libc::c_int, info: &libc::siginfo_t| {
        // Block the signal on this non-guest thread so the kernel won't
        // deliver it here again, then re-raise as process-directed so a
        // guest thread picks it up.
        //
        // This should only be called by test threads (spawned via cargo test).
        // Other non-guest threads like network worker threads should have already blocked these signals.
        unsafe {
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, signum);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
            let val = info.si_value();
            libc::sigqueue(libc::getpid(), signum, val);
        }
    };

    // Record host-originated signals (SIGINT, SIGALRM, etc.) in the
    // per-thread pending bitmask so the shim can forward them to the guest.
    // TODO: no realtime signal support for now.
    if signum > 0 && signum < 32 {
        // For timer-originated signals (and their re-raises via `sigqueue`),
        // the desired guest signal is encoded in `si_value.sival_ptr`
        // (set by `create_timer`).  For other sources (e.g. `kill()`), use
        // the signal number directly.
        let guest_signum = if info.si_code == libc::SI_TIMER || info.si_code == libc::SI_QUEUE {
            unsafe { info.si_value().sival_ptr as libc::c_int }
        } else {
            signum
        };

        // Only record signals that can be forwarded to the guest as
        // litebox_common_linux::signal::Signal. Unknown signals are silently dropped.
        let Ok(signal) = litebox_common_linux::signal::Signal::try_from(guest_signum) else {
            return;
        };

        // Check whether this is a guest thread. If not, re-raise the signal
        // process-wide.
        //
        // This asks a *thread-lifetime* question -- "was this thread ever
        // handed to `run_thread_arch`?" -- not "is guest code executing right
        // now?". Do NOT substitute `in_guest` here: `in_guest` is momentary
        // and is 0 whenever a guest thread is sitting in the host, including
        // while it is parked in an interruptible wait. That parked case is
        // precisely what `record_pending_signal` and `wait_waker_addr` exist
        // to serve, so using `in_guest` would route it down the re-raise path
        // and drop the wakeup.
        let is_guest_thread;
        #[cfg(target_arch = "x86_64")]
        {
            let gsbase: u64;
            unsafe { core::arch::asm!("rdgsbase {}", out(reg) gsbase) };
            is_guest_thread = gsbase != 0;
        }
        // AArch64 has no register that incidentally encodes this the way
        // `gsbase` does on x86-64, so it is recorded explicitly.
        #[cfg(target_arch = "aarch64")]
        {
            is_guest_thread = self::is_guest_thread();
        }

        if is_guest_thread {
            // SAFETY: we verified the saved host TLS segment is valid above.
            unsafe { record_pending_signal(signal) };
        } else {
            #[cfg(debug_assertions)]
            raise_signal(signum, info);
            return;
        }
    }

    // The interrupt signal can arrive in different contexts:
    // 1. The thread is running in the host at the beginning of the syscall
    //    handler. Do nothing--the syscall handler will handle the interrupt.
    // 2. The thread is running in the host, with in_guest = 0. Just record that
    //    an interrupt is pending; it will be checked next time we switch to the
    //    guest.
    // 3. The thread is running in the host, with in_guest = 1, in the middle of
    //    restoring the guest context. We need to jump to the interrupt handler
    //    without overwriting the saved guest context.
    // 4. The thread is running in the guest. We need to save the context and
    //    jump to the interrupt handler.
    //
    // Note that this signal can't arrive while in an exception signal handler
    // since we mask the interrupt signal while handling exceptions.

    #[cfg(target_arch = "x86_64")]
    let ip = context.uc_mcontext.gregs[libc::REG_RIP as usize]
        .reinterpret_as_unsigned()
        .trunc();
    #[cfg(target_arch = "aarch64")]
    let ip = context.uc_mcontext.pc.trunc();

    // Case 1: at the beginning of the syscall handler.
    //
    // FUTURE: handle trampoline code, too. This is somewhat less important
    // because it's probably fine for the shim to observe a guest context that
    // is inside the trampoline.
    if ip == syscall_callback as *const () as usize {
        // No need to clear `in_guest` or set interrupt; the syscall handler will
        // clear `in_guest` and call into the shim.
        return;
    }

    // Clear `in_guest` and set `interrupt`.
    let Some(regs) = signal_handler_exit_guest(context, true) else {
        // Case 2: not in guest.
        return;
    };

    // If the interrupt happened while returning to the guest, don't overwrite
    // the saved context.
    let in_switch_to_guest = (switch_to_guest_start as *const () as usize
        ..switch_to_guest_end as *const () as usize)
        .contains(&ip);
    if in_switch_to_guest {
        // Case 3: in the middle of restoring guest context. Don't overwrite it.
    } else {
        // Case 4: in guest. Copy out the context.
        copy_signal_context(unsafe { &mut *regs }, context);
    }
    // Cases 3 and 4: jump to interrupt handler.
    set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
}

impl litebox::platform::CrngProvider for LinuxUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

impl litebox::platform::DerivedKeyProvider for LinuxUserland {
    fn derive_key<E>(
        &self,
        shim_kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(boot_id) = self.boot_id.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        };
        match shim_kdf {
            None => {
                // TODO: Ideally, we'd use something like argon2 or such here to support more shims,
                // but for now, we just return an error.
                Err(litebox::platform::DerivedKeyError::ShimKDFRequired)
            }
            Some(shim_kdf) => {
                // We trust the shim in this platform, since it is in the same trust boundary as us.
                // Thus (unlike some other platforms) we do not need to manually hide the "key", and
                // can just run the KDF as-is.
                //
                // Our key is actually just the boot ID itself.
                Ok(shim_kdf(boot_id, params)?)
            }
        }
    }
}

/// Dummy `VmapManager`.
///
/// In general, userland platforms do not support `vmap` and `vunmap` (which are kernel functions).
/// We might need to emulate these functions' behaviors using virtual addresses for development or
/// testing, or use a kernel module to provide this functionality (if needed).
unsafe impl<const ALIGN: usize> VmapManager<ALIGN> for LinuxUserland {
    type MapInfo = litebox_common_linux::vmap::NoopPhysPageMapInfo;

    fn validate_unowned(
        &self,
        _pages: &litebox_common_linux::vmap::PhysPageAddrArray<ALIGN>,
    ) -> Result<(), litebox_common_linux::vmap::PhysPointerError> {
        Err(litebox_common_linux::vmap::PhysPointerError::UnsupportedOperation)
    }

    unsafe fn protect(
        &self,
        _pages: &litebox_common_linux::vmap::PhysPageAddrArray<ALIGN>,
        _perms: litebox_common_linux::vmap::PhysPageMapPermissions,
    ) -> Result<(), litebox_common_linux::vmap::PhysPointerError> {
        Err(litebox_common_linux::vmap::PhysPointerError::UnsupportedOperation)
    }
}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Linux kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for LinuxUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Linux userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Linux userland")
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    // These are used only by `test_seccomp_filter`, which is x86-64 only
    // because `enable_seccomp_filter` is.
    #[cfg(target_arch = "x86_64")]
    use std::net::Shutdown;
    #[cfg(target_arch = "x86_64")]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    #[cfg(target_arch = "x86_64")]
    use std::os::unix::net::UnixStream;
    use std::thread::sleep;

    #[cfg(target_arch = "x86_64")]
    use litebox::fs::OFlags;
    use litebox::platform::RawMutex;

    use crate::LinuxUserland;
    use litebox::platform::PageManagementProvider;

    extern crate std;

    /// TLS layout is a property of a whole link, so this only validates the
    /// test harness binary — not the shipped runner, which links a different
    /// set of crates. A green run here is not a validated production layout;
    /// the real safety net is `assert_tls_layout()` in `LinuxUserland::new`.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_tls_layout() {
        super::assert_tls_layout();
    }

    /// Pins the `PtRegs` field offsets that the AArch64 transition assembly
    /// hardcodes. A field reorder or insertion in `litebox_common_linux`
    /// would otherwise silently corrupt the guest context.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_ptregs_layout() {
        use core::mem::offset_of;
        use litebox_common_linux::PtRegs;

        assert_eq!(core::mem::size_of::<PtRegs>(), 288);
        assert_eq!(core::mem::align_of::<PtRegs>(), 16);
        // `regs[N]` lives at `8 * N`; spot-check the one the assembly names
        // explicitly.
        assert_eq!(offset_of!(PtRegs, regs) + 16 * 8, 128);
        assert_eq!(offset_of!(PtRegs, sp), 248);
        assert_eq!(offset_of!(PtRegs, pc), 256);
        assert_eq!(offset_of!(PtRegs, pstate), 264);
        assert_eq!(offset_of!(PtRegs, orig_x0), 272);
        assert_eq!(offset_of!(PtRegs, syscallno), 280);
    }

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex
                .inner
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = LinuxUserland::new(None);
        let reserved_pages: Vec<_> =
            <LinuxUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }

    /// `LinuxUserland::enable_seccomp_filter` is itself gated to x86-64 (the
    /// rule list names syscalls such as `poll` that do not exist on AArch64),
    /// so the test that exercises it is gated the same way.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_seccomp_filter() {
        fn test_memfd(name: &std::ffi::CStr) -> OwnedFd {
            // SAFETY: `name` is a valid C string and the returned descriptor is
            // transferred immediately into `OwnedFd`.
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            assert!(fd >= 0);
            // SAFETY: `fd` was just returned as an owned descriptor.
            unsafe { OwnedFd::from_raw_fd(fd) }
        }

        let _platform: &LinuxUserland = LinuxUserland::new(None);
        let allowed = test_memfd(c"seccomp-allowed-positional-io");
        let denied = test_memfd(c"seccomp-denied-positional-io");
        let (allowed_shutdown, _allowed_peer) = UnixStream::pair().unwrap();
        let (denied_shutdown, _denied_peer) = UnixStream::pair().unwrap();
        LinuxUserland::enable_seccomp_filter(
            &[allowed.as_raw_fd()],
            &[allowed_shutdown.as_raw_fd()],
        );

        let written = [7_u8];
        // SAFETY: The buffers are valid for their lengths, and both descriptors
        // remain open for the calls.
        assert_eq!(
            unsafe {
                libc::pwrite(
                    allowed.as_raw_fd(),
                    written.as_ptr().cast(),
                    written.len(),
                    0,
                )
            },
            1
        );
        let mut read = [0_u8];
        // SAFETY: See the `pwrite` call above.
        assert_eq!(
            unsafe { libc::pread(allowed.as_raw_fd(), read.as_mut_ptr().cast(), read.len(), 0,) },
            1
        );
        assert_eq!(read, written);
        // SAFETY: See the allowed `pwrite` call above.
        assert_eq!(
            unsafe {
                libc::pwrite(
                    denied.as_raw_fd(),
                    written.as_ptr().cast(),
                    written.len(),
                    0,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
        let error = allowed_shutdown.shutdown(Shutdown::Write).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        allowed_shutdown.shutdown(Shutdown::Both).unwrap();
        let error = denied_shutdown.shutdown(Shutdown::Both).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));

        let pathname = c"/tmp/test_seccomp";
        let mkdir_res = unsafe {
            syscalls::syscall2(syscalls::Sysno::mkdir, pathname.as_ptr() as usize, 0o755)
        };
        assert_eq!(
            mkdir_res.unwrap_err(),
            syscalls::Errno::EINVAL,
            "mkdir should be blocked by seccomp filter"
        );

        // The filter allows `openat` only when the flags argument is exactly
        // `O_RDONLY`, so both halves of that condition need pinning: without
        // the RDONLY case a missing/misnumbered rule would go unnoticed, and
        // without the RDWR case the condition could be dropped entirely.
        let pathname =
            std::ffi::CString::new(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let open_rdonly = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                super::AT_FDCWD,
                pathname.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let fd = open_rdonly.expect("openat with RDONLY should be allowed by seccomp filter");
        // SAFETY: `openat` just returned this as a fresh owned descriptor.
        drop(unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) });

        let open_rdwr = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                super::AT_FDCWD,
                pathname.as_ptr() as usize,
                OFlags::RDWR.bits() as usize,
                0,
            )
        };
        assert_eq!(
            open_rdwr.unwrap_err(),
            syscalls::Errno::EINVAL,
            "openat with RDWR should be blocked by seccomp filter"
        );
    }
}
