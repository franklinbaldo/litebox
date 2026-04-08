// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]
#![allow(
    // Windows ABI entrypoints and packet interfaces require these integer widths.
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    // Raw pointer conversions are inherent to the userland platform glue.
    clippy::borrow_as_ptr,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr,
    clippy::ptr_cast_constness,
    clippy::ref_as_ptr,
    // Some helpers define local items after probing platform state.
    clippy::items_after_statements,
    // Interop helpers intentionally use panic assertions and underscored fields.
    clippy::missing_panics_doc,
    clippy::unused_self,
    clippy::used_underscore_binding,
)]

#[cfg(all(debug_assertions, feature = "trace_debug"))]
macro_rules! trace_debugln {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}

#[cfg(not(all(debug_assertions, feature = "trace_debug")))]
macro_rules! trace_debugln {
    ($($arg:tt)*) => {};
}

#[cfg(feature = "trace_debug")]
fn append_trace_debug_log(msg: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};

    static TRACE_FILE: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();

    let file = TRACE_FILE.get_or_init(|| {
        let path = std::env::temp_dir().join(format!(
            "litebox_platform_windows_userland_trace_{}.log",
            std::process::id()
        ));
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Mutex::new(file)
    });

    if let Ok(mut guard) = file.lock()
        && let Some(file) = guard.as_mut()
    {
        let _ = file.write_all(msg.as_bytes());
    }
}

use core::cell::Cell;
use core::panic;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::raw::c_void;
use std::os::windows::io::AsRawHandle as _;
use std::sync::{Arc, Mutex, OnceLock};

use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{
    AllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::shim::{ContinueOperation, Exception};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::PunchthroughSyscall;

use windows_sys::Win32::Foundation::{self as Win32_Foundation, CloseHandle, FILETIME};
use windows_sys::Win32::{
    Foundation::GetLastError,
    Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_PRIMARY_GROUP,
        TOKEN_QUERY, TOKEN_USER, TokenPrimaryGroup, TokenUser,
    },
    System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, CONTEXT_XSTATE_AMD64, EXCEPTION_CONTINUE_EXECUTION,
        EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, EXCEPTION_RECORD, GetXStateFeaturesMask,
        InitializeContext, LocateXStateFeature, SetXStateFeaturesMask,
    },
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::SystemInformation::{self as Win32_SysInfo, GetSystemTimePreciseAsFileTime},
    System::Threading::{self as Win32_Threading, GetCurrentProcess},
    System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise,
};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

#[derive(Clone, Copy)]
struct UnixLikeIdentity {
    uid: u32,
    gid: u32,
}

/// IPC stream to a host-side broker.
///
/// On Windows, both loopback TCP sockets and AF_UNIX sockets are Winsock
/// stream sockets. Rust's standard library only exposes `TcpStream`, so both
/// variants are owned through that type while remaining explicitly tagged here.
#[derive(Debug)]
pub enum IpcStream {
    Tcp(std::net::TcpStream),
    Unix(std::net::TcpStream),
}

impl IpcStream {
    pub fn from_tcp(stream: std::net::TcpStream) -> Self {
        Self::Tcp(stream)
    }

    pub fn from_unix(stream: std::net::TcpStream) -> Self {
        Self::Unix(stream)
    }

    pub fn set_nonblocking(&self, nonblock: bool) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.set_nonblocking(nonblock),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.set_nodelay(nodelay),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.set_read_timeout(timeout),
        }
    }

    pub fn peek(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.peek(buf),
        }
    }

    pub fn raw_socket(&self) -> usize {
        use std::os::windows::io::AsRawSocket;

        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.as_raw_socket() as usize,
        }
    }
}

impl Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) | Self::Unix(stream) => stream.flush(),
        }
    }
}

// Thread-local storage for FS base state
thread_local! {
    static THREAD_FS_BASE: Cell<usize> = const { Cell::new(0) };
}

// Thread-local storage for the active guest VA range on this host thread.
// NT-mode guest exception handling uses this to reject stale host-side
// CONTEXTs when `is_in_guest` has not been cleared yet.
thread_local! {
    static THREAD_GUEST_VA_START: Cell<usize> = const { Cell::new(0) };
    static THREAD_GUEST_VA_END: Cell<usize> = const { Cell::new(0) };
}

const TRANSITION_TRACE_LEN: usize = 64;

#[derive(Clone, Copy)]
struct TransitionTraceEntry {
    seq: u32,
    kind: u8,
    _pad: [u8; 3],
    detail: u32,
    rip: u64,
    rsp: u64,
    r11: u64,
    rflags: u64,
    mxcsr: u32,
    thread_id: u32,
}

impl TransitionTraceEntry {
    const EMPTY: Self = Self {
        seq: 0,
        kind: 0,
        _pad: [0; 3],
        detail: 0,
        rip: 0,
        rsp: 0,
        r11: 0,
        rflags: 0,
        mxcsr: 0,
        thread_id: 0,
    };
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum TransitionTraceKind {
    SwitchToGuest = 1,
    Syscall = 2,
    VehException = 3,
    ShimException = 4,
    InterruptHandler = 5,
    InterruptInject = 6,
    UnhandledException = 7,
    SingleStep = 8,
    HostContinueGate = 9,
    HostApcGate = 10,
}

impl TransitionTraceKind {
    const fn as_u8(self) -> u8 {
        self as u8
    }

    const fn name(kind: u8) -> &'static str {
        match kind {
            x if x == Self::SwitchToGuest as u8 => "switch_to_guest",
            x if x == Self::Syscall as u8 => "syscall",
            x if x == Self::VehException as u8 => "veh_exception",
            x if x == Self::ShimException as u8 => "shim_exception",
            x if x == Self::InterruptHandler as u8 => "interrupt_handler",
            x if x == Self::InterruptInject as u8 => "interrupt_inject",
            x if x == Self::UnhandledException as u8 => "unhandled_exception",
            x if x == Self::SingleStep as u8 => "single_step",
            x if x == Self::HostContinueGate as u8 => "host_continue_gate",
            x if x == Self::HostApcGate as u8 => "host_apc_gate",
            _ => "unknown",
        }
    }
}

fn read_mxcsr() -> u32 {
    let mut mxcsr = 0u32;
    unsafe {
        core::arch::asm!(
            "stmxcsr DWORD PTR [{ptr}]",
            ptr = in(reg) &raw mut mxcsr,
            options(nostack, preserves_flags)
        );
    }
    mxcsr
}

static DEFAULT_MXCSR_WORD: u32 = 0x1F80;

fn format_transition_detail(kind: u8, detail: u32) -> alloc::string::String {
    match kind {
        x if x == TransitionTraceKind::VehException.as_u8()
            || x == TransitionTraceKind::ShimException.as_u8()
            || x == TransitionTraceKind::UnhandledException.as_u8() =>
        {
            alloc::format!("code=0x{detail:08X}")
        }
        x if x == TransitionTraceKind::InterruptInject.as_u8() => {
            alloc::format!("redirected={detail}")
        }
        x if x == TransitionTraceKind::SingleStep.as_u8() => {
            alloc::format!("remaining={detail}")
        }
        _ => alloc::format!("detail={detail}"),
    }
}

/// VA-partition constants for multi-process support.
///
/// Each guest process is assigned a non-overlapping 1 TiB VA partition.
/// The number of partitions is determined at runtime from the platform's
/// actual maximum user-mode address.
mod va_partitions {
    /// Size of each VA partition (1 TiB).
    pub const PARTITION_SIZE: usize = 1 << 40;

    /// The lowest usable guest address (matches `TASK_ADDR_MIN`).
    pub const VA_MIN: usize = 0x1_0000;
}

/// Hardcoded upper bound for guest VA (one-past-the-end).
///
/// This must not exceed `GetSystemInfo().lpMaximumApplicationAddress + 1`.
/// A `debug_assert` in `WindowsUserland::new()` validates this at runtime.
const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;

/// Tracks which VA partition slots are allocated.
///
/// Uses `Vec<bool>` so the number of slots can be determined at runtime
/// from `GetSystemInfo().lpMaximumApplicationAddress`.
struct PartitionState {
    allocated: alloc::vec::Vec<bool>,
}

impl PartitionState {
    /// Create a new partition state sized for the given VA range.
    fn new(va_max: usize) -> Self {
        let num_slots = va_max / va_partitions::PARTITION_SIZE;
        Self {
            allocated: alloc::vec![false; num_slots],
        }
    }

    /// Number of partition slots.
    fn num_slots(&self) -> usize {
        self.allocated.len()
    }

    /// Claim the next free slot without checking for host allocations.
    ///
    /// Used for the initial address space (slot 0), which shares the VA
    /// partition with the host process. Host allocations in this range are
    /// expected and harmless because the initial guest pages are explicitly
    /// mapped by the loader.
    fn allocate(&mut self) -> Option<u32> {
        for (i, used) in self.allocated.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(i as u32);
            }
        }
        None
    }

    /// Claim the next free slot whose VA range has no host allocations.
    ///
    /// Calls `probe` on each candidate slot's range. If `probe` returns `true`
    /// (clean), the slot is allocated. Slots where `probe` returns `false` are
    /// skipped (not marked allocated — they may become usable later).
    fn allocate_probed(&mut self, probe: impl Fn(core::ops::Range<usize>) -> bool) -> Option<u32> {
        let num_slots = self.num_slots();
        for i in 0..num_slots {
            if !self.allocated[i] {
                let range = Self::compute_range(i as u32, num_slots);
                if probe(range) {
                    self.allocated[i] = true;
                    return Some(i as u32);
                }
            }
        }
        None
    }

    /// Release a previously allocated slot.
    ///
    /// Returns `false` if the slot is out of range or not currently allocated.
    fn deallocate(&mut self, slot: u32) -> bool {
        let idx = slot as usize;
        if idx >= self.num_slots() {
            return false;
        }
        if !self.allocated[idx] {
            return false;
        }
        self.allocated[idx] = false;
        true
    }

    /// Returns `true` if the given slot is currently allocated.
    fn is_allocated(&self, slot: u32) -> bool {
        let idx = slot as usize;
        idx < self.num_slots() && self.allocated[idx]
    }

    /// Return the VA range for the given slot, clipped to `VA_MIN..va_max`.
    fn range_of(&self, slot: u32) -> core::ops::Range<usize> {
        Self::compute_range(slot, self.num_slots())
    }

    /// Compute the VA range for a slot given the total number of slots.
    fn compute_range(slot: u32, num_slots: usize) -> core::ops::Range<usize> {
        let base = (slot as usize) * va_partitions::PARTITION_SIZE;
        let va_max = num_slots * va_partitions::PARTITION_SIZE;
        let start = base.max(va_partitions::VA_MIN);
        let end = (base + va_partitions::PARTITION_SIZE).min(va_max);
        start..end
    }
}

/// Probe a VA range with `VirtualQuery` to check for host allocations.
///
/// Returns `true` if the entire range is free (`MEM_FREE`), meaning no
/// host DLLs, heap, or system allocations occupy it. Used at partition
/// allocation time to skip slots with ASLR-placed host mappings.
fn is_va_range_clean(range: core::ops::Range<usize>) -> bool {
    let mut addr = range.start;
    while addr < range.end {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        let ok = unsafe {
            Win32_Memory::VirtualQuery(
                addr as *const c_void,
                &raw mut mbi,
                core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        };
        if !ok {
            // VirtualQuery failed — treat as unclean to be safe.
            return false;
        }
        if mbi.State != Win32_Memory::MEM_FREE {
            return false;
        }
        addr = mbi.BaseAddress as usize + mbi.RegionSize;
        if addr == 0 {
            break;
        }
    }
    true
}

/// Terminal state shared by all stdio streams backed by the same Windows
/// console. This provides the Linux-compatible terminal attributes that the
/// guest expects (via TCGETS/TCSETS) and a stored window size override (for
/// TIOCSWINSZ round-trip).
struct ConsoleTerminalState {
    attrs: litebox::platform::TerminalAttributes,
    winsize: litebox::platform::WindowSize,
    /// Whether `set_window_size` has been called (enables stored override).
    winsize_overridden: bool,
}

impl Default for ConsoleTerminalState {
    fn default() -> Self {
        Self {
            attrs: litebox::platform::TerminalAttributes::new_default(),
            winsize: litebox::platform::WindowSize {
                rows: 0,
                cols: 0,
                xpixel: 0,
                ypixel: 0,
            },
            winsize_overridden: false,
        }
    }
}

/// Minimal FFI wrapper for WinTUN (Layer-3 TUN driver for Windows).
///
/// Loads `wintun.dll` dynamically via `LoadLibraryW`/`GetProcAddress` to avoid
/// adding a crate dependency. Only the functions needed for IP packet I/O are
/// resolved.
mod wintun_ffi {
    use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HANDLE, HMODULE};
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    type WintunOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> HANDLE;
    type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: HANDLE);
    type WintunStartSessionFn = unsafe extern "system" fn(adapter: HANDLE, capacity: u32) -> HANDLE;
    type WintunEndSessionFn = unsafe extern "system" fn(session: HANDLE);
    type WintunGetReadWaitEventFn = unsafe extern "system" fn(session: HANDLE) -> HANDLE;
    type WintunReceivePacketFn =
        unsafe extern "system" fn(session: HANDLE, packet_size: *mut u32) -> *mut u8;
    type WintunReleaseReceivePacketFn =
        unsafe extern "system" fn(session: HANDLE, packet: *const u8);
    type WintunAllocateSendPacketFn =
        unsafe extern "system" fn(session: HANDLE, packet_size: u32) -> *mut u8;
    type WintunSendPacketFn =
        unsafe extern "system" fn(session: HANDLE, packet: *const u8, packet_size: u32);

    /// Resolved function pointers from `wintun.dll`.
    struct WintunDll {
        _module: HMODULE,
        open_adapter: WintunOpenAdapterFn,
        close_adapter: WintunCloseAdapterFn,
        start_session: WintunStartSessionFn,
        end_session: WintunEndSessionFn,
        get_read_wait_event: WintunGetReadWaitEventFn,
        receive_packet: WintunReceivePacketFn,
        release_receive_packet: WintunReleaseReceivePacketFn,
        allocate_send_packet: WintunAllocateSendPacketFn,
        send_packet: WintunSendPacketFn,
    }

    impl Drop for WintunDll {
        fn drop(&mut self) {
            // Safety: _module is a valid HMODULE from a successful LoadLibraryW.
            unsafe {
                FreeLibrary(self._module);
            }
        }
    }

    /// Encode a Rust `&str` as a null-terminated UTF-16 wide string.
    fn to_wide(s: &str) -> alloc::vec::Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    /// Resolve a single function pointer from a loaded DLL.
    ///
    /// # Safety
    ///
    /// The caller must ensure `module` is a valid HMODULE and the resolved
    /// pointer matches the expected function signature `T`.
    unsafe fn resolve<T: Copy>(module: HMODULE, name: &[u8]) -> Result<T, String> {
        // Safety: `name` is a null-terminated byte slice, module is valid.
        let proc = unsafe { GetProcAddress(module, name.as_ptr()) };
        match proc {
            Some(p) => {
                // Safety: caller guarantees T matches the actual function signature.
                Ok(unsafe { core::mem::transmute_copy(&p) })
            }
            None => Err(format!(
                "GetProcAddress failed for {}: error {}",
                core::str::from_utf8(&name[..name.len() - 1]).unwrap_or("?"),
                unsafe { GetLastError() }
            )),
        }
    }

    impl WintunDll {
        /// Load `wintun.dll` from the given path and resolve all required exports.
        fn load(dll_path: &str) -> Result<Self, String> {
            let wide_path = to_wide(dll_path);
            // Safety: wide_path is a valid null-terminated UTF-16 string.
            let module = unsafe { LoadLibraryW(wide_path.as_ptr()) };
            if module.is_null() {
                return Err(format!(
                    "LoadLibraryW({dll_path}) failed: error {}",
                    unsafe { GetLastError() }
                ));
            }
            // Safety: module is a valid HMODULE; function name byte strings are
            // null-terminated and the type parameters match the WinTUN ABI.
            unsafe {
                Ok(Self {
                    _module: module,
                    open_adapter: resolve(module, b"WintunOpenAdapter\0")?,
                    close_adapter: resolve(module, b"WintunCloseAdapter\0")?,
                    start_session: resolve(module, b"WintunStartSession\0")?,
                    end_session: resolve(module, b"WintunEndSession\0")?,
                    get_read_wait_event: resolve(module, b"WintunGetReadWaitEvent\0")?,
                    receive_packet: resolve(module, b"WintunReceivePacket\0")?,
                    release_receive_packet: resolve(module, b"WintunReleaseReceivePacket\0")?,
                    allocate_send_packet: resolve(module, b"WintunAllocateSendPacket\0")?,
                    send_packet: resolve(module, b"WintunSendPacket\0")?,
                })
            }
        }
    }

    /// An active WinTUN session for sending and receiving IP packets.
    ///
    /// Owns the adapter and session handles. Dropping this struct ends the
    /// session and closes the adapter.
    pub struct WinTunSession {
        dll: WintunDll,
        adapter: HANDLE,
        session: HANDLE,
        read_wait_event: HANDLE,
    }

    // Safety: WinTUN session handles are thread-safe — the DLL synchronises
    // internally with ring buffer atomics.
    unsafe impl Send for WinTunSession {}
    unsafe impl Sync for WinTunSession {}

    /// Maximum ring buffer capacity for WinTUN sessions (0x400_0000 = 64 MiB).
    const WINTUN_MAX_RING_CAPACITY: u32 = 0x400_0000;

    impl WinTunSession {
        /// Open an existing WinTUN adapter by name and start a packet session.
        ///
        /// The adapter must already exist (created by the `wintun_create_adapter`
        /// tool running as Administrator).
        ///
        /// `dll_path` is the filesystem path to `wintun.dll`.
        /// `adapter_name` is the human-readable adapter name (e.g. "litebox0").
        pub fn open(dll_path: &str, adapter_name: &str) -> Result<Self, String> {
            let dll = WintunDll::load(dll_path)?;
            let wide_name = to_wide(adapter_name);

            // Safety: wide_name is a valid null-terminated UTF-16 string.
            let adapter = unsafe { (dll.open_adapter)(wide_name.as_ptr()) };
            if adapter.is_null() {
                return Err(format!(
                    "WintunOpenAdapter('{adapter_name}') failed: error {}. \
                     Create the adapter first with: wintun_create_adapter {adapter_name}",
                    unsafe { GetLastError() }
                ));
            }

            // Safety: adapter is a valid, non-null WinTUN adapter handle.
            let session = unsafe { (dll.start_session)(adapter, WINTUN_MAX_RING_CAPACITY) };
            if session.is_null() {
                // Safety: adapter is valid — close it before returning error.
                unsafe { (dll.close_adapter)(adapter) };
                return Err(format!("WintunStartSession failed: error {}", unsafe {
                    GetLastError()
                }));
            }

            // Safety: session is a valid, non-null WinTUN session handle.
            let read_wait_event = unsafe { (dll.get_read_wait_event)(session) };

            Ok(Self {
                dll,
                adapter,
                session,
                read_wait_event,
            })
        }

        /// Send an IP packet through the TUN interface.
        pub fn send(&self, packet: &[u8]) -> Result<(), i32> {
            let len = packet.len() as u32;
            // Safety: session is valid; requesting `len` bytes for send buffer.
            let buf = unsafe { (self.dll.allocate_send_packet)(self.session, len) };
            if buf.is_null() {
                let err = unsafe { GetLastError() } as i32;
                return Err(err);
            }
            // Safety: WinTUN guarantees `buf` points to at least `len` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(packet.as_ptr(), buf, packet.len());
                (self.dll.send_packet)(self.session, buf, len);
            }
            Ok(())
        }

        /// Try to receive an IP packet (non-blocking).
        ///
        /// Returns `Ok(n)` with number of bytes written to `out`, or
        /// `Err(ERROR_NO_MORE_ITEMS)` when no packet is available.
        pub fn try_receive(&self, out: &mut [u8]) -> Result<usize, i32> {
            let mut pkt_size: u32 = 0;
            // Safety: session is valid; pkt_size is a valid output pointer.
            let pkt = unsafe { (self.dll.receive_packet)(self.session, &mut pkt_size) };
            if pkt.is_null() {
                let err = unsafe { GetLastError() } as i32;
                return Err(err);
            }
            let n = (pkt_size as usize).min(out.len());
            // Safety: WinTUN guarantees `pkt` points to `pkt_size` bytes.
            // We must release the packet even if it's larger than `out`.
            unsafe {
                core::ptr::copy_nonoverlapping(pkt, out.as_mut_ptr(), n);
                (self.dll.release_receive_packet)(self.session, pkt);
            }
            Ok(n)
        }

        /// Get the Windows event HANDLE that is signalled when a packet is ready
        /// to be received. Use with `WaitForSingleObject` for efficient polling.
        pub fn read_wait_event(&self) -> HANDLE {
            self.read_wait_event
        }
    }

    impl Drop for WinTunSession {
        fn drop(&mut self) {
            // Safety: session and adapter are valid handles obtained from
            // WintunStartSession/WintunOpenAdapter.
            unsafe {
                (self.dll.end_session)(self.session);
                (self.dll.close_adapter)(self.adapter);
            }
        }
    }
}

/// The userland Windows platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct WindowsUserland {
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    slot0_guest_reservations: Mutex<alloc::vec::Vec<core::ops::Range<usize>>>,
    sys_info: std::sync::RwLock<Win32_SysInfo::SYSTEM_INFO>,
    partitions: Mutex<PartitionState>,
    prefer_slot0_for_first_address_space: core::sync::atomic::AtomicBool,
    prefer_redzone_syscall_entry: core::sync::atomic::AtomicBool,
    /// Shared console terminal state for all stdio streams backed by the same
    /// Windows console. Protected by a mutex for thread safety (guest threads
    /// may call TCGETS/TCSETS concurrently).
    console_terminal: Mutex<ConsoleTerminalState>,
    /// Atomic flag for cancelling pending `read_from_stdin()` calls.
    stdin_cancelled: core::sync::atomic::AtomicBool,
    /// Serialize host-stdin consumption so nonblocking reads do not race other
    /// sandbox threads on the shared Windows stdin handle.
    stdin_read_serial: Mutex<()>,
    /// WinTUN session for IP packet I/O (None when networking is disabled).
    tun_session: Option<wintun_ffi::WinTunSession>,
    /// IPC stream to a network broker (None when IPC networking is disabled).
    /// Uses the same framing protocol as the Linux platform: `[u32 LE len][IP packet]`.
    ipc_stream: std::sync::OnceLock<Mutex<IpcStream>>,
    /// Set when the IPC transport encounters a fatal protocol error or EOF.
    ipc_dead: core::sync::atomic::AtomicBool,
}

impl core::fmt::Debug for WindowsUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowsUserland").finish_non_exhaustive()
    }
}

// Safety: Given that SYSTEM_INFO is not Send/Sync (it contains *mut c_void), we use RwLock to
// ensure that the sys_info is only accessed in a thread-safe manner.
// Moreover, SYSTEM_INFO is only initialized once during platform creation, and it is read-only
// after that.
unsafe impl Send for WindowsUserland {}
unsafe impl Sync for WindowsUserland {}

/// Helper functions for managing per-thread FS base
impl WindowsUserland {
    /// Get the current thread's FS base state
    fn get_thread_fs_base() -> usize {
        THREAD_FS_BASE.get()
    }

    /// Set the current thread's FS base
    fn set_thread_fs_base(new_base: usize) {
        THREAD_FS_BASE.set(new_base);
        Self::restore_thread_fs_base();
    }

    /// Restore the current thread's FS base from saved state
    fn restore_thread_fs_base() {
        unsafe {
            litebox_common_linux::wrfsbase(THREAD_FS_BASE.get());
        }
    }

    /// Initialize FS base state for a new thread
    fn init_thread_fs_base() {
        Self::set_thread_fs_base(0);
    }
}

/// Guest TEB base management for NT-mode (Windows PE) guests.
///
/// When running NT-mode guests, FS must point to the guest's synthesized TEB
/// so that rewritten `fs:[...]` accesses in guest code see the correct TEB/PEB.
/// The platform handles FS transitions via THREAD_FS_BASE + VEH repair.
///
/// GS is always the host TEB (never swapped to guest). All guest `gs:` prefixes
/// are rewritten to `fs:` at PE load time. The kernel clobbers FS to 0 on
/// context switches, which is caught by the existing VEH handler.
impl WindowsUserland {
    /// Set the guest TEB base for the current thread.
    ///
    /// Must be called before [`run_thread`] / [`run_thread_ref`] on the
    /// thread that will execute the guest.
    pub fn set_guest_teb_base(value: u64) {
        Self::set_thread_fs_base(value as usize);
    }

    /// Returns the configured guest TEB base for the current host thread.
    pub fn current_guest_teb_base() -> u64 {
        get_tls_ptr().map_or_else(
            || THREAD_FS_BASE.get() as u64,
            |ptr| unsafe { &*ptr }.guest_teb_base.get(),
        )
    }

    /// Set the active guest VA range for the current thread.
    pub fn set_guest_va_range(range: core::ops::Range<usize>) {
        THREAD_GUEST_VA_START.set(range.start);
        THREAD_GUEST_VA_END.set(range.end);
        if let Some(ptr) = get_tls_ptr() {
            let tls = unsafe { &*ptr };
            tls.guest_va_start.set(range.start);
            tls.guest_va_end.set(range.end);
        }
    }

    /// Register the syscall trampoline page range so that NtContinue/NtContinueEx
    /// gate checks can distinguish trampoline code (transition code in guest VA)
    /// from real guest code.  Resumes into the trampoline must NOT be gated
    /// because `switch_to_guest` would re-apply guest FS base, breaking the
    /// trampoline's jump-to-host that may have already started.
    pub fn set_syscall_trampoline_range(start: usize, end: usize) {
        SYSCALL_TRAMPOLINE_START.store(start, Ordering::Release);
        SYSCALL_TRAMPOLINE_END.store(end, Ordering::Release);
    }

    /// Arm a short single-step probe for the current thread's next guest entry.
    pub fn arm_post_continue_single_step_budget(steps: u32) {
        if let Some(ptr) = get_tls_ptr() {
            unsafe { &*ptr }.post_continue_step_budget.set(steps);
        }
    }

    /// Read the opt-in startup GS probe budget from the environment.
    pub fn startup_gs_probe_budget() -> u32 {
        static STARTUP_GS_PROBE_BUDGET: OnceLock<u32> = OnceLock::new();
        *STARTUP_GS_PROBE_BUDGET.get_or_init(|| {
            std::env::var("LITEBOX_STARTUP_GS_STEPS")
                .ok()
                .and_then(|raw| raw.parse::<u32>().ok())
                .map_or(0, |steps| steps.min(256))
        })
    }

    /// Read opt-in guest `ntdll` RVAs where a one-shot INT3 should capture the
    /// raw pre-VEH FS/GS base for diagnostic purposes.
    pub fn guest_gs_breakpoint_probe_rvas() -> &'static [usize] {
        static GUEST_GS_BREAKPOINT_PROBE_RVAS: OnceLock<alloc::vec::Vec<usize>> = OnceLock::new();
        GUEST_GS_BREAKPOINT_PROBE_RVAS
            .get_or_init(|| {
                std::env::var("LITEBOX_GS_BREAKPOINT_RVAS")
                    .ok()
                    .map(|raw| {
                        let mut rvas = alloc::vec::Vec::new();
                        for token in raw.split(|ch: char| {
                            ch == ',' || ch == ';' || ch.is_ascii_whitespace()
                        }) {
                            let token = token.trim();
                            if token.is_empty() {
                                continue;
                            }
                            let parsed = token
                                .strip_prefix("0x")
                                .or_else(|| token.strip_prefix("0X"))
                                .map_or_else(
                                    || token.parse::<usize>().ok(),
                                    |hex| usize::from_str_radix(hex, 16).ok(),
                                );
                            if let Some(rva) = parsed {
                                if !rvas.contains(&rva) && rvas.len() < 32 {
                                    rvas.push(rva);
                                }
                            } else {
                                eprintln!(
                                    "[litebox] ignoring invalid LITEBOX_GS_BREAKPOINT_RVAS token: {token}"
                                );
                            }
                        }
                        rvas
                    })
                    .unwrap_or_default()
            })
            .as_slice()
    }

    /// Dump the current thread's transition ring, if platform TLS is installed.
    pub fn dump_current_transition_trace(label: &str) {
        if let Some(ptr) = get_tls_ptr() {
            unsafe { &*ptr }.dump_transition_trace(label);
        } else {
            eprintln!("[{label}] transition trace unavailable: platform TLS not initialized");
        }
    }
}

/// Address of host `ntdll!RtlDispatchException + 12`, i.e. the first
/// instruction after the detour-overwritten prologue pushes.
static RTL_DISPATCH_EXCEPTION_CONTINUE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Address of host `ntdll!RtlRestoreContext + 12`, i.e. the first instruction
/// after the detour-overwritten prologue stores/pushes.
static RTL_RESTORE_CONTEXT_CONTINUE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Address of host `ntdll!KiUserApcDispatcher + 15`, i.e. the first
/// instruction after the detour-overwritten prologue.
static KI_USER_APC_DISPATCHER_CONTINUE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Address of host `ntdll!KiUserApcDispatcher + 0x2E`, i.e. the instruction
/// after the helper call returns from the normal APC routine.
static KI_USER_APC_AFTER_ROUTINE_CONTINUE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Install the host `RtlDispatchException` detour at most once.
static INSTALL_RTL_DISPATCH_EXCEPTION_HOOK: std::sync::Once = const { std::sync::Once::new() };

/// Install the host `RtlRestoreContext` detour at most once.
static INSTALL_RTL_RESTORE_CONTEXT_HOOK: std::sync::Once = const { std::sync::Once::new() };

/// Install the host `NtContinue` detour at most once.
static INSTALL_NT_CONTINUE_HOOK: std::sync::Once = const { std::sync::Once::new() };

/// Install the host `NtContinueEx` detour at most once.
static INSTALL_NT_CONTINUE_EX_HOOK: std::sync::Once = const { std::sync::Once::new() };

/// Install the host `KiUserApcDispatcher` detour at most once.
static INSTALL_KI_USER_APC_DISPATCHER_HOOK: std::sync::Once = const { std::sync::Once::new() };

/// Address of host `ntdll!KiUserCallbackDispatcher + 14`, i.e. the first
/// instruction after the detour-overwritten prologue.
static KI_USER_CALLBACK_DISPATCHER_CONTINUE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Install the host `KiUserCallbackDispatcher` detour at most once.
static INSTALL_KI_USER_CALLBACK_DISPATCHER_HOOK: std::sync::Once = const { std::sync::Once::new() };

/// Address of host `ntdll!KiRaiseUserExceptionDispatcher + 14`, i.e. the
/// first instruction after the detour-overwritten prologue.
static KI_RAISE_USER_EXCEPTION_DISPATCHER_CONTINUE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Install the host `KiRaiseUserExceptionDispatcher` detour at most once.
static INSTALL_KI_RAISE_USER_EXCEPTION_DISPATCHER_HOOK: std::sync::Once =
    const { std::sync::Once::new() };

/// Start of the syscall trampoline code page in guest VA.
/// The NtContinue/NtContinueEx gate must NOT gate resumes into this range,
/// because the trampoline is transition code (jump to host syscall callback)
/// that happens to live in guest VA space.
static SYSCALL_TRAMPOLINE_START: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// End (exclusive) of the syscall trampoline code page in guest VA.
static SYSCALL_TRAMPOLINE_END: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Naked trampoline for the host `ntdll!RtlDispatchException` detour.
///
/// Problem: when guest code faults after `NtContinue`, the Windows kernel
/// dispatches the exception through the host process's `RtlDispatchException`
/// with FS still pointing at the guest TEB base. Host ntdll then reads
/// `gs:[0x60]` / `gs:[0x30]` from the host PEB/TEB (GS is host TEB) but
/// our VEH may need to run first to restore FS.
///
/// We detour the host `RtlDispatchException` entry and replicate the original
/// 12-byte prologue (`0x40` REX prefix + 7 callee-saved pushes). GS is always
/// host TEB now (no GS table scan needed), so the trampoline simply replays
/// the prologue and jumps to the original function body.
#[unsafe(naked)]
unsafe extern "system" fn rtl_dispatch_exception_trampoline() -> ! {
    core::arch::naked_asm!(
        // Replicate the original first 12 bytes of ntdll!RtlDispatchException:
        //   0x40; push rbp; push rsi; push rdi; push r12; push r13; push r14; push r15
        ".byte 0x40",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // GS is always host TEB now (no guest GS swap), so just replay the
        // prologue and jump to the original function body.
        "mov rax, QWORD PTR [rip + {RTL_DISPATCH_EXCEPTION_CONTINUE}]",
        "jmp rax",
        RTL_DISPATCH_EXCEPTION_CONTINUE = sym RTL_DISPATCH_EXCEPTION_CONTINUE,
    );
}

/// Copy a guest-targeted host CONTEXT into LiteBox's saved guest state so the
/// thread can resume through `interrupt_callback` / `switch_to_guest`.
unsafe extern "system" fn rtl_restore_context_should_gate(
    context_ptr: *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) -> bool {
    let Some(tls_ptr) = get_tls_ptr() else {
        return false;
    };
    let tls = unsafe { &*tls_ptr };
    if tls.guest_teb_base.get() == 0 {
        return false;
    }
    if !is_readable_committed_range(
        context_ptr as usize,
        core::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>(),
    ) {
        return false;
    }

    let Some(context) = (unsafe { context_ptr.as_ref() }) else {
        return false;
    };
    let rip = context.Rip.truncate();
    if !tls.guest_va_contains(rip) {
        return false;
    }

    // The syscall trampoline lives in guest VA but is transition code (jump to
    // host syscall_callback).  If a kernel callback/APC interrupted the
    // trampoline and the post-callback NtContinue resumes here, we must
    // NOT gate: switch_to_guest would re-apply guest FS base, and the
    // trampoline's jump to host may have already started.  Let the
    // original NtContinue handle the resume.
    let tramp_start = SYSCALL_TRAMPOLINE_START.load(Ordering::Acquire);
    let tramp_end = SYSCALL_TRAMPOLINE_END.load(Ordering::Acquire);
    if tramp_start != 0 && rip >= tramp_start && rip < tramp_end {
        return false;
    }

    let exec_ctx = unsafe {
        &mut *(tls.guest_context_top.get().wrapping_sub(1)
            as *mut litebox_common_linux::ExecutionContext)
    };
    save_guest_context(exec_ctx, context, context_ptr);
    tls.trace_transition(
        TransitionTraceKind::HostContinueGate,
        0,
        context.Rip,
        context.Rsp,
        context.R11,
        context.EFlags.into(),
    );
    true
}

/// Common gate for host `NtContinue` / `NtContinueEx` exports.
unsafe extern "system" fn nt_continue_should_gate(
    context_ptr: *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) -> bool {
    unsafe { rtl_restore_context_should_gate(context_ptr) }
}

/// Prepare a guest APC routine to run through LiteBox instead of letting host
/// `KiUserApcDispatcher` jump to the guest target directly.
unsafe extern "system" fn ki_user_apc_dispatch_should_gate(
    normal_routine: usize,
    normal_context: usize,
    system_arg1: usize,
    system_arg2: usize,
    frame_rsp: usize,
) -> bool {
    let Some(tls_ptr) = get_tls_ptr() else {
        return false;
    };
    let tls = unsafe { &*tls_ptr };
    if tls.guest_teb_base.get() == 0 || !tls.guest_va_contains(normal_routine) {
        return false;
    }
    if !is_readable_committed_range(
        frame_rsp,
        core::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>(),
    ) {
        return false;
    }
    let Some(guest_rsp) = frame_rsp.checked_sub(core::mem::size_of::<usize>()) else {
        return false;
    };
    if !is_writable_committed_range(guest_rsp, core::mem::size_of::<usize>()) {
        return false;
    }

    let context_ptr = frame_rsp as *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
    let Some(context) = (unsafe { context_ptr.as_ref() }) else {
        return false;
    };
    let exec_ctx = unsafe {
        &mut *(tls.guest_context_top.get().wrapping_sub(1)
            as *mut litebox_common_linux::ExecutionContext)
    };
    save_guest_context(exec_ctx, context, context_ptr);
    unsafe {
        core::ptr::write(
            guest_rsp as *mut usize,
            apc_return_callback as *const () as usize,
        );
    }
    exec_ctx.regs.rip = normal_routine;
    exec_ctx.regs.rsp = guest_rsp;
    exec_ctx.regs.rax = normal_routine;
    exec_ctx.regs.rcx = normal_context;
    exec_ctx.regs.rdx = system_arg1;
    exec_ctx.regs.r8 = system_arg2;
    exec_ctx.regs.r9 = frame_rsp;
    tls.trace_transition(
        TransitionTraceKind::HostApcGate,
        0,
        normal_routine as u64,
        guest_rsp as u64,
        exec_ctx.regs.r11 as u64,
        exec_ctx.eflags as u64,
    );
    true
}

/// Naked trampoline for the host `ntdll!RtlRestoreContext` detour.
///
/// When host exception dispatch handles a fault on a managed guest thread, host
/// ntdll can restore a guest CONTEXT directly. Gate those resumes through
/// LiteBox's host stack so `switch_to_guest` re-applies guest GS immediately
/// before guest code runs.
#[unsafe(naked)]
unsafe extern "system" fn rtl_restore_context_trampoline() -> ! {
    core::arch::naked_asm!(
        // Replicate the original first 12 bytes of ntdll!RtlRestoreContext:
        //   mov [rsp+0x08], rbx
        //   mov [rsp+0x18], rbp
        //   push rsi
        //   push rdi
        "mov QWORD PTR [rsp + 8], rbx",
        "mov QWORD PTR [rsp + 24], rbp",
        "push rsi",
        "push rdi",
        // GS is always host TEB now (no guest GS swap needed).
        // Preserve the original arguments across the helper call.
        "mov rsi, rcx",
        "mov rdi, rdx",
        "sub rsp, 0x28",
        "mov rcx, rsi",
        "call {gate_helper}",
        "add rsp, 0x28",
        "test al, al",
        "jz 4f",
        // Gate the resume through LiteBox's interrupt callback on the saved
        // host stack. interrupt_callback will handle any pending interrupt and
        // otherwise fall straight through to switch_to_guest.
        "mov r11d, DWORD PTR [rip + {TLS_INDEX}]",
        "cmp r11d, 0xFFFFFFFF",
        "je 4f",
        "mov r11, QWORD PTR gs:[r11 * 8 + 5248]",
        "test r11, r11",
        "jz 4f",
        "mov rsp, QWORD PTR [r11 + {HOST_SP}]",
        "mov rbp, QWORD PTR [r11 + {HOST_BP}]",
        "jmp {interrupt_callback}",
        "4:",
        "mov rcx, rsi",
        "mov rdx, rdi",
        "mov rax, QWORD PTR [rip + {RTL_RESTORE_CONTEXT_CONTINUE}]",
        "jmp rax",
        TLS_INDEX = sym TLS_INDEX,
        HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
        HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
        gate_helper = sym rtl_restore_context_should_gate,
        interrupt_callback = sym interrupt_callback,
        RTL_RESTORE_CONTEXT_CONTINUE = sym RTL_RESTORE_CONTEXT_CONTINUE,
    );
}

/// Naked trampoline for the host `ntdll!NtContinue` detour.
#[unsafe(naked)]
unsafe extern "system" fn nt_continue_trampoline() -> ! {
    core::arch::naked_asm!(
        // GS is always host TEB now (no guest GS swap needed).
        "sub rsp, 0x38",
        "mov QWORD PTR [rsp + 0x20], rcx",
        "mov QWORD PTR [rsp + 0x28], rdx",
        "call {gate_helper}",
        "mov rcx, QWORD PTR [rsp + 0x20]",
        "mov rdx, QWORD PTR [rsp + 0x28]",
        "add rsp, 0x38",
        "test al, al",
        "jz 4f",
        "mov r11d, DWORD PTR [rip + {TLS_INDEX}]",
        "cmp r11d, 0xFFFFFFFF",
        "je 4f",
        "mov r11, QWORD PTR gs:[r11 * 8 + 5248]",
        "test r11, r11",
        "jz 4f",
        "mov rsp, QWORD PTR [r11 + {HOST_SP}]",
        "mov rbp, QWORD PTR [r11 + {HOST_BP}]",
        "jmp {interrupt_callback}",
        "4:",
        // Reconstruct the original syscall stub body.
        "mov r10, rcx",
        "mov eax, 0x43",
        "test byte ptr [0x7ffe0308], 1",
        "jne 5f",
        "syscall",
        "ret",
        "5:",
        "int 0x2e",
        "ret",
        TLS_INDEX = sym TLS_INDEX,
        HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
        HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
        gate_helper = sym nt_continue_should_gate,
        interrupt_callback = sym interrupt_callback,
    );
}

/// Naked trampoline for the host `ntdll!NtContinueEx` detour.
#[unsafe(naked)]
unsafe extern "system" fn nt_continue_ex_trampoline() -> ! {
    core::arch::naked_asm!(
        // GS is always host TEB now (no guest GS swap needed).
        "sub rsp, 0x38",
        "mov QWORD PTR [rsp + 0x20], rcx",
        "mov QWORD PTR [rsp + 0x28], rdx",
        "call {gate_helper}",
        "mov rcx, QWORD PTR [rsp + 0x20]",
        "mov rdx, QWORD PTR [rsp + 0x28]",
        "add rsp, 0x38",
        "test al, al",
        "jz 4f",
        "mov r11d, DWORD PTR [rip + {TLS_INDEX}]",
        "cmp r11d, 0xFFFFFFFF",
        "je 4f",
        "mov r11, QWORD PTR gs:[r11 * 8 + 5248]",
        "test r11, r11",
        "jz 4f",
        "mov rsp, QWORD PTR [r11 + {HOST_SP}]",
        "mov rbp, QWORD PTR [r11 + {HOST_BP}]",
        "jmp {interrupt_callback}",
        "4:",
        // Reconstruct the original syscall stub body.
        "mov r10, rcx",
        "mov eax, 0xA5",
        "test byte ptr [0x7ffe0308], 1",
        "jne 5f",
        "syscall",
        "ret",
        "5:",
        "int 0x2e",
        "ret",
        TLS_INDEX = sym TLS_INDEX,
        HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
        HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
        gate_helper = sym nt_continue_should_gate,
        interrupt_callback = sym interrupt_callback,
    );
}

/// Naked trampoline for the host `ntdll!KiUserApcDispatcher` detour.
///
/// If the APC routine target is guest code, route it through LiteBox so the
/// guest APC runs under `switch_to_guest`, and its post-APC `NtContinueEx`
/// resume is also gated back through LiteBox.
#[unsafe(naked)]
unsafe extern "system" fn ki_user_apc_dispatcher_trampoline() -> ! {
    core::arch::naked_asm!(
        // GS is always host TEB now (no guest GS swap needed).
        // Reconstruct the normal APC path's arguments from the kernel-built frame.
        "mov rax, QWORD PTR [rsp + 24]", // NormalRoutine
        "mov rcx, rax",
        "sar rcx, 2",
        "neg rcx",
        "shld rcx, rcx, 32",
        "test ecx, ecx",
        "je 4f",
        "mov rdx, QWORD PTR [rsp + 8]",  // SystemArgument1
        "mov r8, QWORD PTR [rsp + 16]",  // SystemArgument2
        "mov r9, rsp",                   // CONTEXT frame base
        "mov r10, r9",                   // save frame_rsp
        "mov r11, rdx",                  // save arg1
        "mov rcx, rax",                  // arg0 = NormalRoutine
        "mov rdx, QWORD PTR [rsp]",      // arg1 = NormalContext
        "mov r9, r8",                    // arg3 = SystemArgument2
        "mov r8, r11",                   // arg2 = SystemArgument1
        "ldmxcsr DWORD PTR [rip + {DEFAULT_MXCSR_WORD}]",
        "sub rsp, 0x28",                 // shadow space + arg5
        "mov QWORD PTR [rsp + 0x20], r10", // arg4 = frame_rsp
        "call {gate_helper}",
        "add rsp, 0x28",
        "test al, al",
        "jz 4f",
        // Gate guest APC entry through LiteBox's host stack.
        "mov r11d, DWORD PTR [rip + {TLS_INDEX}]",
        "cmp r11d, 0xFFFFFFFF",
        "je 4f",
        "mov r11, QWORD PTR gs:[r11 * 8 + 5248]",
        "test r11, r11",
        "jz 4f",
        "mov rsp, QWORD PTR [r11 + {HOST_SP}]",
        "mov rbp, QWORD PTR [r11 + {HOST_BP}]",
        "jmp {interrupt_callback}",
        // Not a managed guest APC target: execute the overwritten prologue and
        // fall back into the original dispatcher body.
        "4:",
        "mov rcx, QWORD PTR [rsp + 24]",
        "mov rax, rcx",
        "mov r9, rsp",
        "sar rcx, 2",
        "mov r10, QWORD PTR [rip + {KI_USER_APC_DISPATCHER_CONTINUE}]",
        "jmp r10",
        TLS_INDEX = sym TLS_INDEX,
        HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
        HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
        DEFAULT_MXCSR_WORD = sym DEFAULT_MXCSR_WORD,
        gate_helper = sym ki_user_apc_dispatch_should_gate,
        interrupt_callback = sym interrupt_callback,
        KI_USER_APC_DISPATCHER_CONTINUE = sym KI_USER_APC_DISPATCHER_CONTINUE,
    );
}

/// Host callback used as the synthetic return address for guest APC routines.
///
/// This re-enters LiteBox first when the guest APC routine returns, then either
/// resumes the interrupted guest context through `switch_to_guest` or falls back
/// to host `KiUserApcDispatcher`'s post-routine `NtContinueEx` path.
#[unsafe(naked)]
unsafe extern "system" fn apc_return_callback() -> ! {
    core::arch::naked_asm!(
        // GS is always host TEB now (no guest GS swap needed).
        "mov r11d, DWORD PTR [rip + {TLS_INDEX}]",
        "cmp r11d, 0xFFFFFFFF",
        "je 5f",
        "mov r11, QWORD PTR gs:[r11 * 8 + 5248]",
        "test r11, r11",
        "jz 5f",
        "mov BYTE PTR [r11 + {IS_IN_GUEST}], 0",
        "5:",
        "ldmxcsr DWORD PTR [rip + {DEFAULT_MXCSR_WORD}]",
        "sub rsp, 0x20",
        "mov rcx, rsp",
        "add rcx, 0x20",
        "call {continue_helper}",
        "add rsp, 0x20",
        "test al, al",
        "jz 6f",
        "mov r11d, DWORD PTR [rip + {TLS_INDEX}]",
        "cmp r11d, 0xFFFFFFFF",
        "je 6f",
        "mov r11, QWORD PTR gs:[r11 * 8 + 5248]",
        "test r11, r11",
        "jz 6f",
        "mov rsp, QWORD PTR [r11 + {HOST_SP}]",
        "mov rbp, QWORD PTR [r11 + {HOST_BP}]",
        "jmp {interrupt_callback}",
        "6:",
        "mov rax, QWORD PTR [rip + {KI_USER_APC_AFTER_ROUTINE_CONTINUE}]",
        "jmp rax",
        TLS_INDEX = sym TLS_INDEX,
        HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
        HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
        IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
        DEFAULT_MXCSR_WORD = sym DEFAULT_MXCSR_WORD,
        continue_helper = sym rtl_restore_context_should_gate,
        interrupt_callback = sym interrupt_callback,
        KI_USER_APC_AFTER_ROUTINE_CONTINUE = sym KI_USER_APC_AFTER_ROUTINE_CONTINUE,
    );
}

/// Patch host `ntdll!RtlDispatchException` so exception dispatch always runs
/// with host GS, even if the fault happened while guest GS was active.
fn install_rtl_dispatch_exception_hook() {
    INSTALL_RTL_DISPATCH_EXCEPTION_HOOK.call_once(|| unsafe {
        unsafe extern "system" {
            fn GetModuleHandleA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FlushInstructionCache(
                process: windows_sys::Win32::Foundation::HANDLE,
                base_address: *const c_void,
                size: usize,
            ) -> i32;
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        assert!(!ntdll.is_null(), "Failed to install required RtlDispatchException hook: GetModuleHandleA(ntdll.dll) failed");

        // RtlDispatchException is not exported. Derive its address from the
        // exported KiUserExceptionDispatcher stub:
        //   mov rcx, rsp
        //   add rcx, 0x4F0
        //   mov rdx, rsp
        //   call rel32   ; -> RtlDispatchException
        let dispatcher = GetProcAddress(ntdll, c"KiUserExceptionDispatcher".as_ptr().cast());
        assert!(!dispatcher.is_null(), "Failed to install required RtlDispatchException hook: KiUserExceptionDispatcher export missing");
        let dispatcher = dispatcher.cast::<u8>();

        const DISPATCH_CALL_BLOCK_OFFSET: usize = 0x1C;
        const DISPATCH_CALL_OFFSET: usize = 0x29;
        const DISPATCH_CALL_BLOCK_PREFIX: [u8; 13] = [
            0x48, 0x8B, 0xCC, // mov rcx, rsp
            0x48, 0x81, 0xC1, 0xF0, 0x04, 0x00, 0x00, // add rcx, 0x4F0
            0x48, 0x8B, 0xD4, // mov rdx, rsp
        ];
        let actual_prefix = core::slice::from_raw_parts(
            dispatcher.add(DISPATCH_CALL_BLOCK_OFFSET),
            DISPATCH_CALL_BLOCK_PREFIX.len(),
        );
        assert!(actual_prefix == DISPATCH_CALL_BLOCK_PREFIX, "Failed to install required RtlDispatchException hook: KiUserExceptionDispatcher call-site pattern changed");
        let call_site = dispatcher.add(DISPATCH_CALL_OFFSET);
        assert!(core::ptr::read(call_site) == 0xE8, "Failed to install required RtlDispatchException hook: expected KiUserExceptionDispatcher call missing");
        let rel32 = core::ptr::read_unaligned(call_site.add(1).cast::<i32>()) as isize;
        let target = call_site.add(5).offset(rel32).cast::<u8>();

        const DETOUR_LEN: usize = 12; // mov rax, imm64; jmp rax
        const RTL_DISPATCH_EXCEPTION_PROLOGUE: [u8; DETOUR_LEN] = [
            0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
        ];
        let actual_prologue = core::slice::from_raw_parts(target, DETOUR_LEN);
        assert!(actual_prologue == RTL_DISPATCH_EXCEPTION_PROLOGUE, "Failed to install required RtlDispatchException hook: RtlDispatchException prologue changed");
        RTL_DISPATCH_EXCEPTION_CONTINUE.store(target as usize + DETOUR_LEN, Ordering::Release);

        let hook_addr = rtl_dispatch_exception_trampoline as *const () as usize as u64;
        let mut detour = [0u8; DETOUR_LEN];
        detour[0] = 0x48; // mov rax, imm64
        detour[1] = 0xB8;
        detour[2..10].copy_from_slice(&hook_addr.to_le_bytes());
        detour[10] = 0xFF; // jmp rax
        detour[11] = 0xE0;

        let mut old_protect = 0u32;
        let protect_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        assert!(protect_ok != 0, "Failed to install required RtlDispatchException hook: VirtualProtect failed");

        // Safety: the page is temporarily RWX and DETOUR_LEN exactly matches
        // the validated RtlDispatchException prologue we intentionally replace.
        core::ptr::copy_nonoverlapping(detour.as_ptr(), target, DETOUR_LEN);

        let flush_ok = FlushInstructionCache(GetCurrentProcess(), target.cast(), DETOUR_LEN);
        assert!(flush_ok != 0, "Failed to install required RtlDispatchException hook: FlushInstructionCache failed");

        let mut _ignored_old = 0u32;
        let restore_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            old_protect,
            &mut _ignored_old,
        );
        assert!(restore_ok != 0, "Failed to install required RtlDispatchException hook: failed to restore page protections");
    });
}

/// Patch host `ntdll!RtlRestoreContext` so guest-targeted handled-exception
/// resumes re-enter LiteBox's gate instead of jumping straight back to guest
/// code with host GS active.
fn install_rtl_restore_context_hook() {
    INSTALL_RTL_RESTORE_CONTEXT_HOOK.call_once(|| unsafe {
        unsafe extern "system" {
            fn GetModuleHandleA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FlushInstructionCache(
                process: windows_sys::Win32::Foundation::HANDLE,
                base_address: *const c_void,
                size: usize,
            ) -> i32;
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        assert!(
            !ntdll.is_null(),
            "Failed to install required RtlRestoreContext hook: GetModuleHandleA(ntdll.dll) failed"
        );
        let target = GetProcAddress(ntdll, c"RtlRestoreContext".as_ptr().cast()).cast::<u8>();
        assert!(
            !target.is_null(),
            "Failed to install required RtlRestoreContext hook: export missing"
        );

        const DETOUR_LEN: usize = 12; // mov rax, imm64; jmp rax
        const RTL_RESTORE_CONTEXT_PROLOGUE: [u8; DETOUR_LEN] = [
            0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+0x08], rbx
            0x48, 0x89, 0x6C, 0x24, 0x18, // mov [rsp+0x18], rbp
            0x56, // push rsi
            0x57, // push rdi
        ];
        let actual_prologue = core::slice::from_raw_parts(target, DETOUR_LEN);
        assert!(
            actual_prologue == RTL_RESTORE_CONTEXT_PROLOGUE,
            "Failed to install required RtlRestoreContext hook: prologue changed"
        );
        RTL_RESTORE_CONTEXT_CONTINUE.store(target as usize + DETOUR_LEN, Ordering::Release);

        let hook_addr = rtl_restore_context_trampoline as *const () as usize as u64;
        let mut detour = [0u8; DETOUR_LEN];
        detour[0] = 0x48;
        detour[1] = 0xB8;
        detour[2..10].copy_from_slice(&hook_addr.to_le_bytes());
        detour[10] = 0xFF;
        detour[11] = 0xE0;

        let mut old_protect = 0u32;
        let protect_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        assert!(
            protect_ok != 0,
            "Failed to install required RtlRestoreContext hook: VirtualProtect failed"
        );

        core::ptr::copy_nonoverlapping(detour.as_ptr(), target, DETOUR_LEN);

        let flush_ok = FlushInstructionCache(GetCurrentProcess(), target.cast(), DETOUR_LEN);
        assert!(
            flush_ok != 0,
            "Failed to install required RtlRestoreContext hook: FlushInstructionCache failed"
        );

        let mut _ignored_old = 0u32;
        let restore_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            old_protect,
            &mut _ignored_old,
        );
        assert!(
            restore_ok != 0,
            "Failed to install required RtlRestoreContext hook: failed to restore page protections"
        );
    });
}

/// Patch host `ntdll!NtContinue` so guest-targeted host resumes re-enter LiteBox
/// before guest code runs.
fn install_nt_continue_hook() {
    INSTALL_NT_CONTINUE_HOOK.call_once(|| unsafe {
        unsafe extern "system" {
            fn GetModuleHandleA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FlushInstructionCache(
                process: windows_sys::Win32::Foundation::HANDLE,
                base_address: *const c_void,
                size: usize,
            ) -> i32;
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        assert!(
            !ntdll.is_null(),
            "Failed to install required NtContinue hook: GetModuleHandleA(ntdll.dll) failed"
        );
        let target = GetProcAddress(ntdll, c"NtContinue".as_ptr().cast()).cast::<u8>();
        assert!(
            !target.is_null(),
            "Failed to install required NtContinue hook: export missing"
        );

        const DETOUR_LEN: usize = 16;
        const NT_CONTINUE_PROLOGUE: [u8; DETOUR_LEN] = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x43, 0x00, 0x00, 0x00, // mov eax, 0x43
            0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, // test byte ptr [0x7ffe0308],1
        ];
        let actual_prologue = core::slice::from_raw_parts(target, DETOUR_LEN);
        assert!(
            actual_prologue == NT_CONTINUE_PROLOGUE,
            "Failed to install required NtContinue hook: prologue changed"
        );
        let hook_addr = nt_continue_trampoline as *const () as usize as u64;
        let mut detour = [0x90u8; DETOUR_LEN];
        detour[0] = 0x48;
        detour[1] = 0xB8;
        detour[2..10].copy_from_slice(&hook_addr.to_le_bytes());
        detour[10] = 0xFF;
        detour[11] = 0xE0;

        let mut old_protect = 0u32;
        let protect_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        assert!(
            protect_ok != 0,
            "Failed to install required NtContinue hook: VirtualProtect failed"
        );

        core::ptr::copy_nonoverlapping(detour.as_ptr(), target, DETOUR_LEN);

        let flush_ok = FlushInstructionCache(GetCurrentProcess(), target.cast(), DETOUR_LEN);
        assert!(
            flush_ok != 0,
            "Failed to install required NtContinue hook: FlushInstructionCache failed"
        );

        let mut _ignored_old = 0u32;
        let restore_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            old_protect,
            &mut _ignored_old,
        );
        assert!(
            restore_ok != 0,
            "Failed to install required NtContinue hook: failed to restore page protections"
        );
    });
}

/// Patch host `ntdll!NtContinueEx` so guest-targeted host resumes re-enter LiteBox
/// before guest code runs.
fn install_nt_continue_ex_hook() {
    INSTALL_NT_CONTINUE_EX_HOOK.call_once(|| unsafe {
        unsafe extern "system" {
            fn GetModuleHandleA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FlushInstructionCache(
                process: windows_sys::Win32::Foundation::HANDLE,
                base_address: *const c_void,
                size: usize,
            ) -> i32;
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        assert!(
            !ntdll.is_null(),
            "Failed to install required NtContinueEx hook: GetModuleHandleA(ntdll.dll) failed"
        );
        let target = GetProcAddress(ntdll, c"NtContinueEx".as_ptr().cast()).cast::<u8>();
        assert!(
            !target.is_null(),
            "Failed to install required NtContinueEx hook: export missing"
        );

        const DETOUR_LEN: usize = 16;
        const NT_CONTINUE_EX_PROLOGUE: [u8; DETOUR_LEN] = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0xA5, 0x00, 0x00, 0x00, // mov eax, 0xA5
            0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, // test byte ptr [0x7ffe0308],1
        ];
        let actual_prologue = core::slice::from_raw_parts(target, DETOUR_LEN);
        assert!(
            actual_prologue == NT_CONTINUE_EX_PROLOGUE,
            "Failed to install required NtContinueEx hook: prologue changed"
        );
        let hook_addr = nt_continue_ex_trampoline as *const () as usize as u64;
        let mut detour = [0x90u8; DETOUR_LEN];
        detour[0] = 0x48;
        detour[1] = 0xB8;
        detour[2..10].copy_from_slice(&hook_addr.to_le_bytes());
        detour[10] = 0xFF;
        detour[11] = 0xE0;

        let mut old_protect = 0u32;
        let protect_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        assert!(
            protect_ok != 0,
            "Failed to install required NtContinueEx hook: VirtualProtect failed"
        );

        core::ptr::copy_nonoverlapping(detour.as_ptr(), target, DETOUR_LEN);

        let flush_ok = FlushInstructionCache(GetCurrentProcess(), target.cast(), DETOUR_LEN);
        assert!(
            flush_ok != 0,
            "Failed to install required NtContinueEx hook: FlushInstructionCache failed"
        );

        let mut _ignored_old = 0u32;
        let restore_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            old_protect,
            &mut _ignored_old,
        );
        assert!(
            restore_ok != 0,
            "Failed to install required NtContinueEx hook: failed to restore page protections"
        );
    });
}

/// Patch host `ntdll!KiUserApcDispatcher` so guest APC routines do not run
/// directly from host `ntdll`, and the post-APC continue path also re-enters
/// LiteBox before resuming guest code.
fn install_ki_user_apc_dispatcher_hook() {
    INSTALL_KI_USER_APC_DISPATCHER_HOOK.call_once(|| unsafe {
        unsafe extern "system" {
            fn GetModuleHandleA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FlushInstructionCache(
                process: windows_sys::Win32::Foundation::HANDLE,
                base_address: *const c_void,
                size: usize,
            ) -> i32;
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        assert!(
            !ntdll.is_null(),
            "Failed to install required KiUserApcDispatcher hook: GetModuleHandleA(ntdll.dll) failed"
        );
        let target = GetProcAddress(ntdll, c"KiUserApcDispatcher".as_ptr().cast()).cast::<u8>();
        assert!(
            !target.is_null(),
            "Failed to install required KiUserApcDispatcher hook: export missing"
        );

        const DETOUR_LEN: usize = 15; // instruction boundary after `sar rcx, 2`
        const AFTER_HELPER_OFFSET: usize = 0x2E;
        const HELPER_CALL_OFFSET: usize = 0x29;
        const KI_USER_APC_DISPATCHER_PROLOGUE: [u8; DETOUR_LEN] = [
            0x48, 0x8B, 0x4C, 0x24, 0x18, // mov rcx, [rsp+0x18]
            0x48, 0x8B, 0xC1, // mov rax, rcx
            0x4C, 0x8B, 0xCC, // mov r9, rsp
            0x48, 0xC1, 0xF9, 0x02, // sar rcx, 2
        ];
        let actual_prologue = core::slice::from_raw_parts(target, DETOUR_LEN);
        assert!(
            actual_prologue == KI_USER_APC_DISPATCHER_PROLOGUE,
            "Failed to install required KiUserApcDispatcher hook: prologue changed"
        );
        assert!(
            core::ptr::read(target.add(HELPER_CALL_OFFSET)) == 0xE8,
            "Failed to install required KiUserApcDispatcher hook: helper call changed"
        );

        KI_USER_APC_DISPATCHER_CONTINUE.store(target as usize + DETOUR_LEN, Ordering::Release);
        KI_USER_APC_AFTER_ROUTINE_CONTINUE
            .store(target as usize + AFTER_HELPER_OFFSET, Ordering::Release);

        let hook_addr = ki_user_apc_dispatcher_trampoline as *const () as usize as u64;
        let mut detour = [0x90u8; DETOUR_LEN];
        detour[0] = 0x48;
        detour[1] = 0xB8;
        detour[2..10].copy_from_slice(&hook_addr.to_le_bytes());
        detour[10] = 0xFF;
        detour[11] = 0xE0;

        let mut old_protect = 0u32;
        let protect_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        assert!(
            protect_ok != 0,
            "Failed to install required KiUserApcDispatcher hook: VirtualProtect failed"
        );

        core::ptr::copy_nonoverlapping(detour.as_ptr(), target, DETOUR_LEN);

        let flush_ok = FlushInstructionCache(GetCurrentProcess(), target.cast(), DETOUR_LEN);
        assert!(
            flush_ok != 0,
            "Failed to install required KiUserApcDispatcher hook: FlushInstructionCache failed"
        );

        let mut _ignored_old = 0u32;
        let restore_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            old_protect,
            &mut _ignored_old,
        );
        assert!(
            restore_ok != 0,
            "Failed to install required KiUserApcDispatcher hook: failed to restore page protections"
        );
    });
}

/// Naked trampoline for the host `ntdll!KiUserCallbackDispatcher` detour.
///
/// Ensures host GS is active before the dispatcher reads `gs:[0x60]` (PEB)
/// to index into the `KernelCallbackTable`.  Re-executes the overwritten
/// prologue and falls through to the original dispatcher body.
#[unsafe(naked)]
unsafe extern "system" fn ki_user_callback_dispatcher_trampoline() -> ! {
    core::arch::naked_asm!(
        // GS is always host TEB now (no guest GS swap needed).
        // Re-execute the overwritten prologue (14 bytes / 3 instructions):
        //   mov rcx, [rsp+0x20]    (48 8B 4C 24 20)
        //   mov edx, [rsp+0x28]    (8B 54 24 28)
        //   mov r8d, [rsp+0x2C]    (44 8B 44 24 2C)
        "mov rcx, QWORD PTR [rsp + 0x20]",
        "mov edx, DWORD PTR [rsp + 0x28]",
        "mov r8d, DWORD PTR [rsp + 0x2C]",
        // Jump to the original dispatcher body after the detoured region.
        "mov rax, QWORD PTR [rip + {KI_USER_CALLBACK_DISPATCHER_CONTINUE}]",
        "jmp rax",
        KI_USER_CALLBACK_DISPATCHER_CONTINUE = sym KI_USER_CALLBACK_DISPATCHER_CONTINUE,
    );
}

/// Patch host `ntdll!KiUserCallbackDispatcher` so user-mode callbacks always
/// run with host GS active, preventing guest-TEB/PEB reads from the host
/// dispatcher code.
fn install_ki_user_callback_dispatcher_hook() {
    INSTALL_KI_USER_CALLBACK_DISPATCHER_HOOK.call_once(|| unsafe {
        unsafe extern "system" {
            fn GetModuleHandleA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FlushInstructionCache(
                process: windows_sys::Win32::Foundation::HANDLE,
                base_address: *const c_void,
                size: usize,
            ) -> i32;
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        assert!(
            !ntdll.is_null(),
            "Failed to install required KiUserCallbackDispatcher hook: GetModuleHandleA(ntdll.dll) failed"
        );
        let target =
            GetProcAddress(ntdll, c"KiUserCallbackDispatcher".as_ptr().cast()).cast::<u8>();
        assert!(
            !target.is_null(),
            "Failed to install required KiUserCallbackDispatcher hook: export missing"
        );

        const DETOUR_LEN: usize = 14;
        const KI_USER_CALLBACK_DISPATCHER_PROLOGUE: [u8; DETOUR_LEN] = [
            0x48, 0x8B, 0x4C, 0x24, 0x20, // mov rcx, [rsp+0x20]
            0x8B, 0x54, 0x24, 0x28, // mov edx, [rsp+0x28]
            0x44, 0x8B, 0x44, 0x24, 0x2C, // mov r8d, [rsp+0x2C]
        ];
        let actual_prologue = core::slice::from_raw_parts(target, DETOUR_LEN);
        assert!(
            actual_prologue == KI_USER_CALLBACK_DISPATCHER_PROLOGUE,
            "Failed to install required KiUserCallbackDispatcher hook: prologue changed"
        );

        KI_USER_CALLBACK_DISPATCHER_CONTINUE
            .store(target as usize + DETOUR_LEN, Ordering::Release);

        let hook_addr = ki_user_callback_dispatcher_trampoline as *const () as usize as u64;
        let mut detour = [0x90u8; DETOUR_LEN];
        detour[0] = 0x48;
        detour[1] = 0xB8;
        detour[2..10].copy_from_slice(&hook_addr.to_le_bytes());
        detour[10] = 0xFF;
        detour[11] = 0xE0;

        let mut old_protect = 0u32;
        let protect_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        assert!(
            protect_ok != 0,
            "Failed to install required KiUserCallbackDispatcher hook: VirtualProtect failed"
        );

        core::ptr::copy_nonoverlapping(detour.as_ptr(), target, DETOUR_LEN);

        let flush_ok = FlushInstructionCache(GetCurrentProcess(), target.cast(), DETOUR_LEN);
        assert!(
            flush_ok != 0,
            "Failed to install required KiUserCallbackDispatcher hook: FlushInstructionCache failed"
        );

        let mut _ignored_old = 0u32;
        let restore_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            old_protect,
            &mut _ignored_old,
        );
        assert!(
            restore_ok != 0,
            "Failed to install required KiUserCallbackDispatcher hook: failed to restore page protections"
        );
    });
}

/// Naked trampoline for the host `ntdll!KiRaiseUserExceptionDispatcher` detour.
///
/// Ensures host GS is active before the dispatcher reads `gs:[0x2C0]`
/// (`TEB.LastStatusValue`).  Re-executes the overwritten prologue and falls
/// through to the original dispatcher body.
#[unsafe(naked)]
unsafe extern "system" fn ki_raise_user_exception_dispatcher_trampoline() -> ! {
    core::arch::naked_asm!(
        // GS is always host TEB now (no guest GS swap needed).
        // Re-execute the overwritten prologue (14 bytes / 2 instructions):
        //   sub rsp, 0xC8              (48 81 EC C8 00 00 00)
        //   mov [rsp+0xC0], eax        (89 84 24 C0 00 00 00)
        "sub rsp, 0xC8",
        "mov DWORD PTR [rsp + 0xC0], eax",
        // Jump to the original dispatcher body after the detoured region.
        "mov rax, QWORD PTR [rip + {KI_RAISE_USER_EXCEPTION_DISPATCHER_CONTINUE}]",
        "jmp rax",
        KI_RAISE_USER_EXCEPTION_DISPATCHER_CONTINUE = sym KI_RAISE_USER_EXCEPTION_DISPATCHER_CONTINUE,
    );
}

/// Patch host `ntdll!KiRaiseUserExceptionDispatcher` so that when the kernel
/// converts a kernel-mode exception to a user-mode one, the dispatcher always
/// runs with host GS active.
fn install_ki_raise_user_exception_dispatcher_hook() {
    INSTALL_KI_RAISE_USER_EXCEPTION_DISPATCHER_HOOK.call_once(|| unsafe {
        unsafe extern "system" {
            fn GetModuleHandleA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FlushInstructionCache(
                process: windows_sys::Win32::Foundation::HANDLE,
                base_address: *const c_void,
                size: usize,
            ) -> i32;
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        assert!(
            !ntdll.is_null(),
            "Failed to install required KiRaiseUserExceptionDispatcher hook: GetModuleHandleA(ntdll.dll) failed"
        );
        let target = GetProcAddress(
            ntdll,
            c"KiRaiseUserExceptionDispatcher".as_ptr().cast(),
        )
        .cast::<u8>();
        assert!(
            !target.is_null(),
            "Failed to install required KiRaiseUserExceptionDispatcher hook: export missing"
        );

        const DETOUR_LEN: usize = 14;
        const KI_RAISE_USER_EXCEPTION_DISPATCHER_PROLOGUE: [u8; DETOUR_LEN] = [
            0x48, 0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00, // sub rsp, 0xC8
            0x89, 0x84, 0x24, 0xC0, 0x00, 0x00, 0x00, // mov [rsp+0xC0], eax
        ];
        let actual_prologue = core::slice::from_raw_parts(target, DETOUR_LEN);
        assert!(
            actual_prologue == KI_RAISE_USER_EXCEPTION_DISPATCHER_PROLOGUE,
            "Failed to install required KiRaiseUserExceptionDispatcher hook: prologue changed"
        );

        KI_RAISE_USER_EXCEPTION_DISPATCHER_CONTINUE
            .store(target as usize + DETOUR_LEN, Ordering::Release);

        let hook_addr =
            ki_raise_user_exception_dispatcher_trampoline as *const () as usize as u64;
        let mut detour = [0x90u8; DETOUR_LEN];
        detour[0] = 0x48;
        detour[1] = 0xB8;
        detour[2..10].copy_from_slice(&hook_addr.to_le_bytes());
        detour[10] = 0xFF;
        detour[11] = 0xE0;

        let mut old_protect = 0u32;
        let protect_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        assert!(
            protect_ok != 0,
            "Failed to install required KiRaiseUserExceptionDispatcher hook: VirtualProtect failed"
        );

        core::ptr::copy_nonoverlapping(detour.as_ptr(), target, DETOUR_LEN);

        let flush_ok = FlushInstructionCache(GetCurrentProcess(), target.cast(), DETOUR_LEN);
        assert!(
            flush_ok != 0,
            "Failed to install required KiRaiseUserExceptionDispatcher hook: FlushInstructionCache failed"
        );

        let mut _ignored_old = 0u32;
        let restore_ok = VirtualProtect(
            target.cast::<c_void>(),
            DETOUR_LEN,
            old_protect,
            &mut _ignored_old,
        );
        assert!(
            restore_ok != 0,
            "Failed to install required KiRaiseUserExceptionDispatcher hook: failed to restore page protections"
        );
    });
}

/// Naked asm trampoline for the VEH handler.
///
/// GS is always host TEB now (the kernel restores it on context switch),
/// so the trampoline simply calls the Rust VEH handler directly — no
/// GS save/restore is needed.
///
/// This naked trampoline:
/// 1. Allocates shadow space per the Windows x64 ABI
/// 2. Calls the real Rust VEH handler
#[unsafe(naked)]
unsafe extern "system" fn vectored_exception_handler_trampoline(
    _exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    core::arch::naked_asm!(
        // GS is always host TEB now — no GS save/scan/restore needed.
        // Just call the real Rust VEH handler directly.
        "sub rsp, 0x28",              // shadow space + alignment for Windows x64 ABI
        "call {real_handler}",
        "add rsp, 0x28",
        "ret",
        real_handler = sym vectored_exception_handler_inner,
    );
}

/// The real VEH handler, called from the trampoline after GS is restored.
unsafe extern "system" fn vectored_exception_handler_inner(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    let (info, exception_record, context);
    unsafe {
        info = *exception_info;
        exception_record = &*info.ExceptionRecord;
        context = &mut *info.ContextRecord;
    }

    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    {
        static VEH_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = VEH_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let is_breakpoint =
            exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_BREAKPOINT;
        if n < 200 || is_breakpoint {
            let current_gs: u64;
            unsafe {
                core::arch::asm!("rdgsbase {}", out(reg) current_gs, options(nostack, preserves_flags));
            }
            let (guest_teb_val, pre_veh_scratch) = get_tls_ptr().map_or((0, 0), |p| {
                let tls = unsafe { &*p };
                (tls.guest_teb_base.get(), tls.scratch.get() as u64)
            });
            trace_debugln!(
                "[VEH] #{} code=0x{:08X} rip=0x{:X} addr=0x{:X} gs=0x{:X} guest_teb=0x{:X} scratch=0x{:X}{}{}",
                n,
                exception_record.ExceptionCode as u32,
                context.Rip,
                if exception_record.NumberParameters >= 2 {
                    exception_record.ExceptionInformation[1] as u64
                } else {
                    0
                },
                current_gs,
                guest_teb_val,
                pre_veh_scratch,
                if current_gs == guest_teb_val {
                    " GS=GUEST_TEB!"
                } else {
                    ""
                },
                if pre_veh_scratch == guest_teb_val {
                    " PRE=GUEST_TEB!"
                } else if pre_veh_scratch == current_gs {
                    " PRE=HOST!"
                } else {
                    ""
                },
            );
        }
        // GS lookup failed — print diagnostics and abort.
        if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ILLEGAL_INSTRUCTION {
            let current_gs: u64;
            unsafe {
                core::arch::asm!("rdgsbase {}", out(reg) current_gs, options(nostack, preserves_flags));
            }
            let r11 = context.R11;
            let rip = context.Rip;
            let host_tid = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
            let mut msg = alloc::format!(
                "\n[FATAL] Illegal instruction!\n  RIP=0x{rip:X}  R11=0x{r11:X}  current_gs=0x{current_gs:X}\n  host_tid={host_tid}\n"
            );
            if let Some(tls) = get_tls_ptr() {
                let tls = unsafe { &*tls };
                use core::fmt::Write;
                let _ = writeln!(
                    msg,
                    "  TlsState.guest_teb_base=0x{:X}  is_in_guest={}",
                    tls.guest_teb_base.get(),
                    tls.is_in_guest.get()
                );
            } else {
                msg.push_str("  TlsState: NOT INSTALLED\n");
            }
            let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
            std::process::abort();
        }
    }

    let Some(tls) = get_tls_ptr() else {
        // TLS slot not initialized yet; cannot be in guest.
        return EXCEPTION_CONTINUE_SEARCH;
    };
    let tls = unsafe { &*tls };
    tls.trace_transition(
        TransitionTraceKind::VehException,
        exception_record.ExceptionCode as u32,
        context.Rip,
        context.Rsp,
        context.R11,
        context.EFlags.into(),
    );

    // If RIP is inside the switch_to_guest asm block, registers are in
    // a partially-restored intermediate state (some guest, some host).
    // We cannot save a valid guest context here.
    let rip = context.Rip as usize;
    if rip >= switch_to_guest_start as *const () as usize
        && rip < switch_to_guest_end as *const () as usize
    {
        const EXCEPTION_SINGLE_STEP: i32 = 0x80000004_u32 as i32;
        if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP
            && tls.post_continue_step_budget.get() != 0
        {
            // A startup single-step probe arms TF before the final guest ret, so
            // the CPU may first trap on a few instructions inside switch_to_guest
            // itself. Keep stepping until RIP leaves the transition stub; only
            // then is the guest context coherent enough to log and redirect.
            context.EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        tls.is_in_guest.set(false);
        tls.dump_transition_trace("veh-switch-window");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if tls.guest_teb_base.get() != 0 && tls.is_in_guest.get() && !tls.guest_va_contains(rip) {
        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        trace_debugln!(
            "[VEH-host] stale is_in_guest for host RIP: rip=0x{:X} guest_range=0x{:X}..0x{:X}",
            rip,
            tls.guest_va_start.get(),
            tls.guest_va_end.get(),
        );
        tls.is_in_guest.set(false);
    }

    // If RIP is inside the syscall trampoline (transition code that lives in
    // guest VA), the thread is entering host mode, not executing real guest
    // code.  Do NOT save the intermediate trampoline state into the
    // ExecutionContext — switch_to_guest would re-apply guest FS base when
    // resuming, breaking the trampoline's jump to host.  Instead, treat this
    // like the switch_to_guest window: clear is_in_guest and let the normal
    // host exception path handle it.
    {
        let tramp_start = SYSCALL_TRAMPOLINE_START.load(Ordering::Acquire);
        let tramp_end = SYSCALL_TRAMPOLINE_END.load(Ordering::Acquire);
        if tramp_start != 0 && rip >= tramp_start && rip < tramp_end && tls.is_in_guest.get() {
            tls.is_in_guest.set(false);
            tls.dump_transition_trace("veh-trampoline-window");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    if !tls.is_in_guest.get() {
        // This might be a faulting guest memory access in LiteBox code. Try to
        // recover.
        if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION
            && let Some(recover) =
                litebox::mm::exception_table::search_exception_tables(context.Rip.truncate())
        {
            // Found a matching exception table entry.
            context.Rip = recover as u64;
            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            // Not one of our exceptions; let other handlers process it.
            #[cfg(all(debug_assertions, feature = "trace_debug"))]
            trace_debugln!(
                "[VEH-host] NOT in guest, CONTINUE_SEARCH: code=0x{:08X} rip=0x{:X} addr=0x{:X}",
                exception_record.ExceptionCode as u32,
                context.Rip,
                if exception_record.NumberParameters >= 2 {
                    exception_record.ExceptionInformation[1] as u64
                } else {
                    0
                },
            );
            tls.dump_transition_trace("veh-host-search");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    tls.is_in_guest.set(false);

    // Handle EXCEPTION_SINGLE_STEP for instruction-level tracing.
    // When TF is set in EFLAGS (by the switch_to_guest code), each guest
    // instruction triggers this exception. We log the RIP and re-set TF
    // so tracing continues.
    const EXCEPTION_SINGLE_STEP: i32 = 0x80000004_u32 as i32;
    if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP {
        let remaining = tls.post_continue_step_budget.get();
        if remaining != 0 {
            let fault_scratch = tls.scratch.get() as u64;
            let guest_teb = tls.guest_teb_base.get();
            // For single-step startup probes, repurpose the trace payload so the
            // dump prints the observed FS/GS pair at each instruction:
            //   rsp    = guest RSP
            //   r11    = fault-time scratch (pre-VEH)
            //   rflags = expected guest TEB base
            tls.trace_transition_with_metadata(
                TransitionTraceKind::SingleStep,
                remaining,
                context.Rip,
                context.Rsp,
                fault_scratch,
                guest_teb,
                read_mxcsr(),
                unsafe { Win32_Threading::GetCurrentThreadId() },
            );
            let next = remaining.saturating_sub(1);
            tls.post_continue_step_budget.set(next);
            if next == 0 {
                tls.dump_transition_trace("post-continue-step");
            } else {
                context.EFlags |= 0x100;
            }
        } else {
            // Preserve the old behavior for unexpected single-step exceptions.
            context.EFlags |= 0x100;
        }
        // Preserve the VEH trampoline invariant: handled exceptions that return
        // EXCEPTION_CONTINUE_EXECUTION must keep host GS active unless they
        // already redirected RIP to a host callback. Go through the interrupt
        // callback so switch_to_guest reapplies guest GS as the final host-side
        // transition step.
        save_context_and_redirect_to_interrupt_callback(tls, context);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Debug output exceptions raised by the guest (e.g., OutputDebugStringA/W
    // under CRT init). These are informational only; silently resume.
    // Preserve the same VEH invariant as the single-step path: bounce through
    // the interrupt callback so guest GS is restored by switch_to_guest, not
    // while host ntdll is still unwinding the exception.
    const DBG_PRINTEXCEPTION_C: u32 = 0x40010006;
    const DBG_PRINTEXCEPTION_WIDE_C: u32 = 0x4001000A;
    if exception_record.ExceptionCode == DBG_PRINTEXCEPTION_C as i32
        || exception_record.ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C as i32
    {
        save_context_and_redirect_to_interrupt_callback(tls, context);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Cast to ExecutionContext — PtRegs is at offset 0 of ExecutionContext, so
    // the pointer to PtRegs is also a valid pointer to ExecutionContext.
    let ctx_top = tls.guest_context_top.get();
    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    {
        let access_type = if exception_record.ExceptionCode as u32 == 0xC0000005
            && exception_record.NumberParameters >= 1
        {
            match exception_record.ExceptionInformation[0] {
                0 => "READ",
                1 => "WRITE",
                8 => "DEP",
                _ => "???",
            }
        } else {
            ""
        };
        static VEH_GUEST_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = VEH_GUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < 32 || n.is_power_of_two() {
            trace_debugln!(
                "[VEH-exc] #{} guest exception: code=0x{:08X} rip=0x{:X} addr=0x{:X} access={} guest_context_top={:p} host_sp={:p}",
                n,
                exception_record.ExceptionCode as u32,
                context.Rip,
                if exception_record.NumberParameters >= 2 {
                    exception_record.ExceptionInformation[1] as u64
                } else {
                    0
                },
                access_type,
                ctx_top,
                tls.host_sp.get(),
            );
        }
    }

    // Enhanced Bug C diagnostics (outside debug_assertions gate): for the first
    // few guest ACCESS_VIOLATION exceptions, dump FS base, VirtualQuery of
    // faulting address, instruction bytes at RIP, and full register state.
    #[cfg(feature = "trace_debug")]
    if exception_record.ExceptionCode as u32 == 0xC0000005 {
        static BUGC_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let bc = BUGC_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if bc < 5 {
            use core::fmt::Write;
            let fault_addr = if exception_record.NumberParameters >= 2 {
                exception_record.ExceptionInformation[1] as usize
            } else {
                0
            };
            let current_fs: u64;
            unsafe {
                core::arch::asm!("rdfsbase {}", out(reg) current_fs, options(nostack, preserves_flags));
            }
            let stored_fs = tls.guest_teb_base.get();
            let rw = if exception_record.NumberParameters >= 1 {
                match exception_record.ExceptionInformation[0] {
                    0 => "READ",
                    1 => "WRITE",
                    8 => "DEP",
                    _ => "???",
                }
            } else { "?" };
            let mut msg = alloc::format!(
                "[VEH-exc-detail] #{bc} ACCESS_VIOLATION {rw} at cr2=0x{fault_addr:X}\n  rdfsbase=0x{current_fs:X} stored_guest_teb=0x{stored_fs:X} is_in_guest={}\n  guest_va=0x{:X}..0x{:X}\n",
                tls.is_in_guest.get(),
                tls.guest_va_start.get(),
                tls.guest_va_end.get(),
            );
            // VirtualQuery the faulting address
            {
                let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                let ok = unsafe {
                    Win32_Memory::VirtualQuery(
                        fault_addr as *const c_void,
                        &raw mut mbi,
                        core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                    ) != 0
                };
                if ok {
                    let _ = writeln!(
                        msg,
                        "  VQ(0x{fault_addr:X}): BaseAddr=0x{:X} AllocBase=0x{:X} Protect=0x{:X} State=0x{:X} Type=0x{:X} RegionSize=0x{:X}",
                        mbi.BaseAddress as usize,
                        mbi.AllocationBase as usize,
                        mbi.Protect,
                        mbi.State,
                        mbi.Type,
                        mbi.RegionSize,
                    );
                } else {
                    let _ = writeln!(msg, "  VQ(0x{fault_addr:X}): FAILED");
                }
            }
            // Read instruction bytes at RIP (if readable)
            {
                let rip_addr = context.Rip as usize;
                let mut rip_mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                let rip_ok = unsafe {
                    Win32_Memory::VirtualQuery(
                        rip_addr as *const c_void,
                        &raw mut rip_mbi,
                        core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                    ) != 0
                };
                if rip_ok && rip_mbi.State == Win32_Memory::MEM_COMMIT {
                    let bytes: &[u8] = unsafe {
                        core::slice::from_raw_parts(rip_addr as *const u8, 16.min(
                            (rip_mbi.BaseAddress as usize + rip_mbi.RegionSize).saturating_sub(rip_addr)
                        ))
                    };
                    let _ = write!(msg, "  insn@0x{rip_addr:X}: ");
                    for b in bytes {
                        let _ = write!(msg, "{b:02X} ");
                    }
                    let _ = writeln!(msg);
                } else {
                    let _ = writeln!(msg, "  insn@0x{rip_addr:X}: NOT READABLE (state=0x{:X})", rip_mbi.State);
                }
            }
            // Full register dump
            let _ = writeln!(
                msg,
                "  regs: rax=0x{:X} rbx=0x{:X} rcx=0x{:X} rdx=0x{:X}\n        rsi=0x{:X} rdi=0x{:X} rbp=0x{:X} rsp=0x{:X}\n        r8=0x{:X} r9=0x{:X} r10=0x{:X} r11=0x{:X}\n        r12=0x{:X} r13=0x{:X} r14=0x{:X} r15=0x{:X}\n        rflags=0x{:X}",
                context.Rax, context.Rbx, context.Rcx, context.Rdx,
                context.Rsi, context.Rdi, context.Rbp, context.Rsp,
                context.R8, context.R9, context.R10, context.R11,
                context.R12, context.R13, context.R14, context.R15,
                context.EFlags,
            );
            let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
        }
    }

    let exec_ctx =
        unsafe { &mut *(ctx_top.wrapping_sub(1) as *mut litebox_common_linux::ExecutionContext) };
    save_guest_context(exec_ctx, context, context as *const _);

    // If it looks like fs base was cleared, then go through the interrupt path
    // instead of the exception path to restore the fs base and try again.
    //
    // This is done instead of just fixing up fsbase and returning here to avoid
    // missing a real interrupt that arrives while resuming the guest. Go through
    // the interrupt path to ensure that any pending interrupts are also handled.
    if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION
        && unsafe { litebox_common_linux::rdfsbase() } == 0
        && WindowsUserland::get_thread_fs_base() != 0
    {
        #[cfg(feature = "trace_debug")]
        eprintln!(
            "[VEH-exc] FS-base-repair: rdfsbase=0, stored=0x{:X}, redirecting to interrupt_callback. rip=0x{:X} cr2=0x{:X}",
            WindowsUserland::get_thread_fs_base(),
            context.Rip,
            if exception_record.NumberParameters >= 2 { exception_record.ExceptionInformation[1] as u64 } else { 0 },
        );
        set_context_to_interrupt_callback(tls, context);
    } else {
        // Store the exception record below host_sp for the exception handler.
        // Safety: the record lives below host_sp (in the stack red-zone), but
        // exception_callback passes the pointer to exception_handler via RDX
        // (the second register parameter). The callee reads the record through
        // this explicit pointer, not via RSP-relative addressing, so normal
        // call-frame growth does not affect access to the data.
        let exception_record_ptr = tls.host_sp.get().cast::<EXCEPTION_RECORD>().wrapping_sub(1);
        debug_assert!(exception_record_ptr.is_aligned());
        unsafe { exception_record_ptr.write(*exception_record) };

        // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
        let _ = run_thread_arch as *const () as usize;

        // Restore RSP to host_sp so that exception_callback can read
        // thread_ctx from [rsp] (same layout as the syscall path).
        // The exception record is below host_sp and passed via RDX.
        context.Rip = exception_callback as *const () as usize as u64;
        context.Rsp = tls.host_sp.get().addr() as u64;
        context.Rbp = tls.host_bp.get() as u64;
        context.Rdx = exception_record_ptr as u64;
    }

    EXCEPTION_CONTINUE_EXECUTION
}

/// Save guest general-purpose registers and FP state from a Windows CONTEXT.
///
/// `context` is used for register values and the 512-byte FXSAVE area.
/// `xstate_ctx_ptr` is the original CONTEXT pointer within its allocation
/// (may be the same as `context`, or point into an extended context buffer).
/// It is used by `LocateXStateFeature` to find AVX upper halves. Pass
/// `core::ptr::null()` to skip XSTATE extraction.
fn save_guest_context(
    guest_context: &mut litebox_common_linux::ExecutionContext,
    context: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    xstate_ctx_ptr: *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
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
    } = &mut guest_context.regs;
    *r15 = context.R15.truncate();
    *r14 = context.R14.truncate();
    *r13 = context.R13.truncate();
    *r12 = context.R12.truncate();
    *rbp = context.Rbp.truncate();
    *rbx = context.Rbx.truncate();
    *r11 = context.R11.truncate();
    *r10 = context.R10.truncate();
    *r9 = context.R9.truncate();
    *r8 = context.R8.truncate();
    *rax = context.Rax.truncate();
    *rcx = context.Rcx.truncate();
    *rdx = context.Rdx.truncate();
    *rsi = context.Rsi.truncate();
    *rdi = context.Rdi.truncate();
    *orig_rax = context.Rax.truncate();
    *rip = context.Rip.truncate();
    *eflags = context.EFlags as usize;
    *rsp = context.Rsp.truncate();

    // Save FP/SIMD state from the CONTEXT's FXSAVE area into FpRegs.
    // The Windows CONTEXT.FltSave (XSAVE_FORMAT) is 512 bytes, matching
    // the first 512 bytes of our FpRegs buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(
            &raw const context.Anonymous.FltSave as *const u8,
            guest_context.fp_regs.data.as_mut_ptr(),
            512,
        );
        // Clear the XSAVE header and AVX upper halves (bytes 512-831) so
        // that any failure to extract XSTATE below results in zeroed upper
        // YMM halves on the next xrstor64, not stale data from a previous
        // fast-path xsave.
        core::ptr::write_bytes(
            guest_context
                .fp_regs
                .data
                .as_mut_ptr()
                .add(XSAVE_HEADER_OFFSET),
            0,
            litebox_common_linux::FP_STATE_SIZE - XSAVE_HEADER_OFFSET,
        );
        // Set xstate_bv bits 0-1 (x87 | SSE) so that xrstor64 restores the
        // legacy FP/SSE state from the FXSAVE area we just copied above.
        // Without these bits, xrstor64 would re-initialize x87/SSE instead
        // of loading the saved values.
        let xstate_bv = guest_context
            .fp_regs
            .data
            .as_mut_ptr()
            .add(XSAVE_HEADER_OFFSET) as *mut u64;
        *xstate_bv = 0x3; // x87 (bit 0) | SSE (bit 1)
    }

    // Try to extract AVX upper halves from the CONTEXT's XSTATE area.
    // On modern Windows, exception CONTEXTs and extended GetThreadContext
    // CONTEXTs contain XSTATE data accessible via LocateXStateFeature.
    // On success this overwrites the zeroed region above with real data.
    if !xstate_ctx_ptr.is_null() {
        extract_avx_from_context(guest_context, xstate_ctx_ptr);
    }
}

/// XSTATE feature ID for AVX (YMM upper halves).
const XSTATE_AVX: u32 = 2;

/// Size of AVX upper halves: 16 YMM registers × 16 bytes (upper 128 bits each).
const XSTATE_AVX_SIZE: usize = 256;

/// Offset within the XSAVE area where AVX upper halves are stored.
/// Layout: [0..512) FXSAVE, [512..576) XSAVE header, [576..832) AVX upper halves.
const XSAVE_AVX_OFFSET: usize = 576;

/// XSAVE header offset within the XSAVE area.
const XSAVE_HEADER_OFFSET: usize = 512;

/// Extract AVX upper halves from a CONTEXT's XSTATE area into FpRegs.
/// `ctx_ptr` must point to the original CONTEXT within its allocation (not a
/// stack copy), because `LocateXStateFeature` navigates relative to it.
///
/// The caller must zero the XSAVE header + AVX region before calling this
/// so that any early-return path leaves clean zeroed state, not stale data.
fn extract_avx_from_context(
    guest_context: &mut litebox_common_linux::ExecutionContext,
    ctx_ptr: *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    unsafe {
        let mut feature_mask: u64 = 0;
        if GetXStateFeaturesMask(ctx_ptr, &mut feature_mask) == 0 {
            return; // CONTEXT has no XSTATE data; buffer already zeroed
        }
        if feature_mask & (1u64 << XSTATE_AVX) == 0 {
            return; // AVX not present; buffer already zeroed
        }
        let mut length: u32 = 0;
        let avx_ptr = LocateXStateFeature(ctx_ptr, XSTATE_AVX, &mut length);
        if avx_ptr.is_null() || (length as usize) < XSTATE_AVX_SIZE {
            return; // Can't locate AVX data; buffer already zeroed
        }
        // Copy the 256-byte AVX upper halves into FpRegs at offset 576.
        core::ptr::copy_nonoverlapping(
            avx_ptr as *const u8,
            guest_context
                .fp_regs
                .data
                .as_mut_ptr()
                .add(XSAVE_AVX_OFFSET),
            XSTATE_AVX_SIZE,
        );
        // Mark AVX as present in the XSAVE header's xstate_bv field.
        let xstate_bv = guest_context
            .fp_regs
            .data
            .as_mut_ptr()
            .add(XSAVE_HEADER_OFFSET) as *mut u64;
        *xstate_bv |= 1u64 << XSTATE_AVX;
    }
}

/// Allocate an extended context buffer with XSTATE support, call
/// `GetThreadContext` on the given thread handle, and return a CONTEXT copy,
/// the original in-buffer pointer (for XSTATE extraction), and the buffer.
///
/// The returned `xstate_ptr` should be passed to `save_guest_context` for
/// AVX extraction via `LocateXStateFeature`. The `_buf` must be kept alive
/// as long as `xstate_ptr` is used.
fn get_extended_thread_context(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> (
    windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    Option<Vec<u8>>,
) {
    use windows_sys::Win32::System::Diagnostics::Debug as Dbg;

    let flags = Dbg::CONTEXT_CONTROL_AMD64
        | Dbg::CONTEXT_INTEGER_AMD64
        | Dbg::CONTEXT_FLOATING_POINT_AMD64
        | CONTEXT_XSTATE_AMD64;

    // Query required buffer size for extended context.
    let mut ctx_len: u32 = 0;
    unsafe {
        InitializeContext(
            core::ptr::null_mut(),
            flags,
            core::ptr::null_mut(),
            &mut ctx_len,
        )
    };

    if ctx_len == 0 {
        // XSTATE not supported; fall back to plain context.
        return get_plain_thread_context(handle);
    }

    // Allocate buffer. InitializeContext handles alignment internally by
    // returning an aligned context pointer within the buffer.
    let mut buf = vec![0u8; ctx_len as usize];

    let mut ctx_ptr: *mut Dbg::CONTEXT = core::ptr::null_mut();
    let r = unsafe {
        InitializeContext(
            buf.as_mut_ptr() as *mut _,
            flags,
            &mut ctx_ptr,
            &mut ctx_len,
        )
    };
    if r == 0 || ctx_ptr.is_null() {
        return get_plain_thread_context(handle);
    }

    // Request AVX state capture.
    unsafe {
        SetXStateFeaturesMask(ctx_ptr, 1u64 << XSTATE_AVX);
    }

    // Capture the thread's register state.
    let r = unsafe { Dbg::GetThreadContext(handle, ctx_ptr) };
    if r == 0 {
        // If extended GetThreadContext fails, try plain.
        return get_plain_thread_context(handle);
    }

    let context = unsafe { *ctx_ptr };
    (context, ctx_ptr as *const _, Some(buf))
}

/// Fall back to a plain (non-extended) CONTEXT for GetThreadContext.
fn get_plain_thread_context(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> (
    windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    *const windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    Option<Vec<u8>>,
) {
    use windows_sys::Win32::System::Diagnostics::Debug as Dbg;
    let mut context = Dbg::CONTEXT {
        ContextFlags: Dbg::CONTEXT_CONTROL_AMD64
            | Dbg::CONTEXT_INTEGER_AMD64
            | Dbg::CONTEXT_FLOATING_POINT_AMD64,
        ..Default::default()
    };
    let r = unsafe { Dbg::GetThreadContext(handle, &raw mut context) };
    assert_ne!(
        r,
        0,
        "GetThreadContext failed: {}",
        std::io::Error::last_os_error()
    );
    // Plain CONTEXT has no XSTATE, so xstate_ptr is null.
    (context, core::ptr::null(), None)
}

impl WindowsUserland {
    /// Opt the next address-space allocation into slot 0 if it is still free.
    ///
    /// This is intended for the Linux-on-Windows single-process runner, where
    /// keeping the init guest in slot 0 lets fixed-address Linux executables
    /// stay at their linked VA instead of being rebased into a clean slot.
    pub fn prefer_slot0_for_first_address_space(&self) {
        self.prefer_slot0_for_first_address_space
            .store(true, Ordering::Relaxed);
    }

    /// Use the SysV-redzone-aware syscall entrypoint for this platform.
    ///
    /// This is intended for the Linux-on-Windows runner, whose syscall
    /// trampolines reserve 128 bytes below RSP before entering the platform.
    /// NT-shim trampolines keep the normal Windows x64 stack layout and must
    /// keep using the plain syscall entrypoint.
    pub fn prefer_redzone_syscall_entry(&self) {
        self.prefer_redzone_syscall_entry
            .store(true, Ordering::Relaxed);
    }

    /// Create a new userland-Windows platform for use in `LiteBox`.
    ///
    /// `tun_device_name` is the name of the WinTUN adapter to open/create for
    /// networking. Pass `None` to disable networking.
    ///
    /// # Panics
    ///
    /// Panics if the TLS slot cannot be created.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        static PLATFORM_INIT_ONCE: core::sync::atomic::AtomicBool =
            core::sync::atomic::AtomicBool::new(false);
        assert!(
            !PLATFORM_INIT_ONCE.swap(true, core::sync::atomic::Ordering::SeqCst),
            "WindowsUserland::new() called more than once — process-global state would be corrupted"
        );

        let mut sys_info = Win32_SysInfo::SYSTEM_INFO::default();
        Self::get_system_information(&mut sys_info);

        let va_min = sys_info.lpMinimumApplicationAddress as usize;
        let va_max = sys_info.lpMaximumApplicationAddress as usize;
        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        {
            trace_debugln!("System information.");
            trace_debugln!("=> Max user address: {va_max:#x}");
            trace_debugln!("=> Min user address: {va_min:#x}");
        }

        // Validate that the hardcoded PageManagementProvider constants are
        // consistent with the runtime values from GetSystemInfo. These run
        // once at startup, so assert! (not debug_assert!) is appropriate.
        assert!(
            va_min <= va_partitions::VA_MIN,
            "runtime lpMinimumApplicationAddress ({va_min:#x}) is above \
             VA_MIN ({:#x})",
            va_partitions::VA_MIN,
        );
        // va_max from GetSystemInfo is the last usable byte (inclusive).
        // TASK_ADDR_MAX is one-past-the-end, so compare without overflow.
        assert!(
            TASK_ADDR_MAX - 1 <= va_max,
            "hardcoded TASK_ADDR_MAX ({TASK_ADDR_MAX:#x}) exceeds runtime \
             lpMaximumApplicationAddress ({va_max:#x})",
        );

        // +1 to convert from inclusive last-byte to exclusive upper bound.
        // Safe: on 64-bit Windows, va_max is always well below usize::MAX.
        let partitions = PartitionState::new(va_max + 1);
        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        trace_debugln!(
            "=> VA partitions: {} slots of {} bytes each",
            partitions.num_slots(),
            va_partitions::PARTITION_SIZE,
        );

        let reserved_pages = Self::read_memory_maps();

        // Initialize WinTUN session if a TUN device name was provided.
        let tun_session = tun_device_name.map(|name| {
            // Look for wintun.dll next to the runner executable first, then
            // fall back to plain "wintun.dll" (system PATH).
            let dll_path = std::env::current_exe()
                .ok()
                .and_then(|p| {
                    let dir = p.parent()?;
                    let candidate = dir.join("wintun.dll");
                    candidate
                        .exists()
                        .then(|| candidate.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "wintun.dll".to_string());
            wintun_ffi::WinTunSession::open(&dll_path, name)
                .unwrap_or_else(|e| panic!("Failed to initialize WinTUN adapter '{name}': {e}"))
        });

        let platform = Self {
            reserved_pages,
            slot0_guest_reservations: Mutex::new(alloc::vec::Vec::new()),
            sys_info: std::sync::RwLock::new(sys_info),
            partitions: Mutex::new(partitions),
            prefer_slot0_for_first_address_space: core::sync::atomic::AtomicBool::new(false),
            prefer_redzone_syscall_entry: core::sync::atomic::AtomicBool::new(false),
            console_terminal: Mutex::new(ConsoleTerminalState::default()),
            stdin_cancelled: core::sync::atomic::AtomicBool::new(false),
            stdin_read_serial: Mutex::new(()),
            tun_session,
            ipc_stream: std::sync::OnceLock::new(),
            ipc_dead: core::sync::atomic::AtomicBool::new(false),
        };

        // Initialize it's own fs-base (for the main thread)
        WindowsUserland::init_thread_fs_base();

        // Windows sets FS_BASE to 0 regularly upon scheduling; we register an exception handler
        // to set FS_BASE back to a "stored" value whenever we notice that it has become 0.
        unsafe {
            let veh_handle =
                AddVectoredExceptionHandler(1, Some(vectored_exception_handler_trampoline));
            assert!(!veh_handle.is_null(), "AddVectoredExceptionHandler failed");
        }

        // Register an unhandled exception filter as a last-resort diagnostic
        // to catch crashes that bypass the VEH handler.
        unsafe {
            unsafe extern "system" fn unhandled_exception_filter(
                info: *const EXCEPTION_POINTERS,
            ) -> i32 {
                unsafe {
                    let info = &*info;
                    let rec = &*info.ExceptionRecord;
                    let ctx = &*info.ContextRecord;
                    if let Some(tls) = get_tls_ptr() {
                        let tls = &*tls;
                        tls.trace_transition(
                            TransitionTraceKind::UnhandledException,
                            rec.ExceptionCode as u32,
                            ctx.Rip,
                            ctx.Rsp,
                            ctx.R11,
                            ctx.EFlags.into(),
                        );
                        tls.dump_transition_trace("unhandled");
                    }
                    unsafe extern "system" {
                        fn GetModuleHandleW(name: *const u16) -> usize;
                    }
                    let image_base = GetModuleHandleW(core::ptr::null());
                    let rva = (ctx.Rip as usize).saturating_sub(image_base);
                    eprintln!(
                        "[UNHANDLED] code=0x{:08X} rip=0x{:X} (rva=0x{:X}) rsp=0x{:X} addr=0x{:X}",
                        rec.ExceptionCode as u32,
                        ctx.Rip,
                        rva,
                        ctx.Rsp,
                        if rec.NumberParameters >= 2 {
                            rec.ExceptionInformation[1] as u64
                        } else {
                            0
                        },
                    );
                    // EXCEPTION_CONTINUE_SEARCH = 0
                    0
                }
            }
            windows_sys::Win32::System::Diagnostics::Debug::SetUnhandledExceptionFilter(Some(
                unhandled_exception_filter,
            ));
        }

        // Register a console control handler to receive Ctrl+C
        unsafe {
            let ok = windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
                Some(ctrl_c_handler),
                1, // TRUE — add the handler
            );
            debug_assert!(ok != 0, "SetConsoleCtrlHandler failed");
        }

        let leaked = Box::leak(Box::new(platform));

        // Install host ntdll detours for exception/APC dispatching.
        install_rtl_dispatch_exception_hook();
        install_rtl_restore_context_hook();
        install_nt_continue_hook();
        install_nt_continue_ex_hook();
        install_ki_user_apc_dispatcher_hook();
        install_ki_user_callback_dispatcher_hook();
        install_ki_raise_user_exception_dispatcher_hook();

        leaked
    }

    /// Attach an IPC stream to the broker for networking.
    ///
    /// The stream must already be connected and in non-blocking mode.
    /// Called after `new()` but before the network worker thread starts.
    /// Panics if called more than once.
    pub fn set_ipc_stream(&self, stream: IpcStream) {
        self.ipc_stream
            .set(Mutex::new(stream))
            .expect("set_ipc_stream called more than once");
    }

    /// Whether any network transport (TUN or IPC) is configured.
    pub fn has_network(&self) -> bool {
        self.tun_session.is_some() || self.ipc_stream.get().is_some()
    }

    /// Mark the IPC transport as dead, causing any in-progress send/receive
    /// to return immediately. Used during shutdown to unblock the network
    /// worker thread.
    pub fn poison_ipc(&self) {
        self.ipc_dead
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }

    fn read_memory_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        let mut reserved_pages = alloc::vec::Vec::new();
        let mut address = 0usize;

        loop {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            let ok = unsafe {
                Win32_Memory::VirtualQuery(
                    address as *const c_void,
                    &raw mut mbi,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                ) != 0
            };
            if !ok {
                break;
            }

            if mbi.State == Win32_Memory::MEM_RESERVE || mbi.State == Win32_Memory::MEM_COMMIT {
                reserved_pages.push(core::ops::Range {
                    start: mbi.BaseAddress as usize,
                    end: (mbi.BaseAddress as usize + mbi.RegionSize),
                });
            }

            address = match (mbi.BaseAddress as usize).checked_add(mbi.RegionSize) {
                Some(a) if a > mbi.BaseAddress as usize => a,
                _ => break,
            };
        }

        reserved_pages
    }

    /// Retrieves information about the host platform (Windows).
    fn get_system_information(sys_info: &mut Win32_SysInfo::SYSTEM_INFO) {
        unsafe {
            Win32_SysInfo::GetSystemInfo(sys_info);
        }
    }

    fn round_up_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        x.checked_add(gran - 1)
            .map_or(usize::MAX, |v| v & !(gran - 1))
    }

    fn round_down_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        x & !(gran - 1)
    }

    fn query_process_token_information(
        class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> alloc::vec::Vec<u8> {
        let mut token = core::ptr::null_mut();
        // SAFETY: We are opening the access token for the current process and
        // provide a valid out-pointer for the returned handle.
        let ok = unsafe {
            Win32_Threading::OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
        };
        if ok == 0 {
            // SAFETY: This reads the thread-local Win32 error code immediately
            // after the failing API call above.
            let err = unsafe { GetLastError() };
            panic!("OpenProcessToken failed: {err}");
        }

        let result = {
            let mut required_len = 0;
            // SAFETY: A null buffer with length 0 is the documented
            // `GetTokenInformation` size-probe pattern, and `required_len` is a
            // valid out-pointer for the required byte count.
            let ok = unsafe {
                GetTokenInformation(token, class, core::ptr::null_mut(), 0, &mut required_len)
            };
            assert_eq!(ok, 0, "GetTokenInformation unexpectedly succeeded");
            // SAFETY: This reads the thread-local Win32 error code immediately
            // after the expected probe failure above.
            let err = unsafe { GetLastError() };
            assert_eq!(
                err,
                Win32_Foundation::ERROR_INSUFFICIENT_BUFFER,
                "GetTokenInformation size probe failed"
            );

            let mut buffer = alloc::vec![0u8; required_len as usize];
            // SAFETY: `buffer` is writable for `required_len` bytes, `token` is
            // still a live TOKEN_QUERY handle, and Windows writes exactly the
            // requested token-information class into the caller-provided buffer.
            let ok = unsafe {
                GetTokenInformation(
                    token,
                    class,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    required_len,
                    &mut required_len,
                )
            };
            if ok == 0 {
                // SAFETY: This reads the thread-local Win32 error code
                // immediately after the failing API call above.
                let err = unsafe { GetLastError() };
                panic!("GetTokenInformation failed: {err}");
            }
            buffer
        };

        // SAFETY: `token` was returned by `OpenProcessToken` above and has not
        // yet been closed.
        let ok = unsafe { CloseHandle(token) };
        if ok == 0 {
            // SAFETY: This reads the thread-local Win32 error code immediately
            // after the failing API call above.
            let err = unsafe { GetLastError() };
            panic!("CloseHandle(token) failed: {err}");
        }

        result
    }

    fn sid_last_subauthority(sid: windows_sys::Win32::Security::PSID) -> u32 {
        assert!(!sid.is_null(), "token SID pointer must not be null");
        // SAFETY: `sid` was checked non-null and comes from Windows
        // token-information structures, so this returns a valid pointer to the
        // SID's subauthority count byte.
        let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
        assert!(
            !count_ptr.is_null(),
            "GetSidSubAuthorityCount returned null"
        );
        // SAFETY: `count_ptr` came from `GetSidSubAuthorityCount` for this SID
        // and points to a single initialized `u8`.
        let count = unsafe { *count_ptr };
        assert!(count > 0, "token SID must have at least one subauthority");
        // SAFETY: `count > 0` guarantees the last-subauthority index is in
        // bounds for this SID, and Windows returns a pointer into the SID
        // storage.
        let subauthority_ptr = unsafe { GetSidSubAuthority(sid, u32::from(count) - 1) };
        assert!(
            !subauthority_ptr.is_null(),
            "GetSidSubAuthority returned null"
        );
        // SAFETY: Token-information buffers are only byte-aligned, so read the
        // final subauthority with an unaligned load rather than assuming `u32`
        // alignment.
        unsafe { core::ptr::read_unaligned(subauthority_ptr) }
    }

    fn current_process_unix_identity() -> UnixLikeIdentity {
        let token_user_buffer = Self::query_process_token_information(TokenUser);
        // SAFETY: `token_user_buffer` owns the raw `TOKEN_USER` bytes returned
        // by Windows and remains alive for the full scope while we follow the
        // embedded SID pointer.
        let token_user =
            unsafe { core::ptr::read_unaligned(token_user_buffer.as_ptr().cast::<TOKEN_USER>()) };

        let token_group_buffer = Self::query_process_token_information(TokenPrimaryGroup);
        // SAFETY: `token_group_buffer` owns the raw `TOKEN_PRIMARY_GROUP`
        // bytes returned by Windows and remains alive for the full scope while
        // we follow the embedded SID pointer.
        let token_group = unsafe {
            core::ptr::read_unaligned(token_group_buffer.as_ptr().cast::<TOKEN_PRIMARY_GROUP>())
        };

        UnixLikeIdentity {
            uid: Self::sid_last_subauthority(token_user.User.Sid),
            gid: Self::sid_last_subauthority(token_group.PrimaryGroup),
        }
    }

    /// Reserve an allocation-granularity-aligned free range with at least
    /// `min_runway` bytes of contiguous space at or above `min_addr`.
    ///
    /// This is used by the Linux-on-Windows loader to choose an initial `brk`
    /// that avoids low host mappings in slot 0 before guest libc starts growing
    /// the heap with fixed-address `brk` calls.
    pub fn reserve_clean_heap_runway(&self, min_addr: usize, min_runway: usize) -> Option<usize> {
        let partition_end =
            min_addr.div_ceil(va_partitions::PARTITION_SIZE) * va_partitions::PARTITION_SIZE;
        let required = self.round_up_to_granu(min_runway.max(1));
        let mut cursor = self.round_down_to_granu(min_addr.max(va_partitions::VA_MIN));
        while cursor < partition_end {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            let ok = unsafe {
                Win32_Memory::VirtualQuery(
                    cursor as *const c_void,
                    &raw mut mbi,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                ) != 0
            };
            if !ok {
                break;
            }
            let region_start = mbi.BaseAddress as usize;
            let Some(next_cursor) = region_start.checked_add(mbi.RegionSize) else {
                break;
            };
            let region_end = next_cursor.min(partition_end);
            if mbi.State == Win32_Memory::MEM_FREE {
                let candidate =
                    self.round_up_to_granu(region_start.max(min_addr).max(va_partitions::VA_MIN));
                if candidate
                    .checked_add(required)
                    .is_some_and(|end| end <= region_end)
                {
                    let ptr = unsafe {
                        VirtualAlloc2(
                            GetCurrentProcess(),
                            candidate as *mut c_void,
                            required,
                            Win32_Memory::MEM_RESERVE,
                            Win32_Memory::PAGE_NOACCESS,
                            core::ptr::null_mut(),
                            0,
                        )
                    };
                    if !ptr.is_null() && ptr as usize == candidate {
                        self.slot0_guest_reservations
                            .lock()
                            .unwrap()
                            .push(candidate..candidate + required);
                        trace_debugln!(
                            "[TRACE-HEAP-RUNWAY] reserved start=0x{:x} len=0x{:x}",
                            candidate,
                            required
                        );
                        return Some(candidate);
                    }
                    if !ptr.is_null() {
                        trace_debugln!(
                            "[TRACE-HEAP-RUNWAY] reserve returned unexpected base=0x{:x} wanted=0x{:x} len=0x{:x}",
                            ptr as usize,
                            candidate,
                            required
                        );
                        let _ = unsafe { VirtualFree(ptr, 0, Win32_Memory::MEM_RELEASE) };
                    }
                }
            }
            cursor = next_cursor;
        }
        None
    }

    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        // Keep PID/PPID in LiteBox's internal process namespace until the core
        // process registry and explicit-PID syscalls are plumbed through a
        // unified host-backed namespace. Windows does not expose POSIX uid/gid
        // values directly, so derive stable guest-visible credentials from the
        // current process token's user and primary-group SIDs.
        let pid = i32::try_from(litebox::process::ProcessId::INIT.0)
            .expect("init pid does not fit in i32");
        let parent_pid = 0;
        let identity = Self::current_process_unix_identity();
        litebox_common_linux::TaskParams {
            pid,
            ppid: parent_pid,
            uid: identity.uid,
            gid: identity.gid,
            euid: identity.uid,
            egid: identity.gid,
        }
    }

    /// Wait for the TUN device to have a packet ready to read, or until
    /// `timeout` expires. Uses `WaitForSingleObject` on the WinTUN read-wait
    /// event for efficient polling.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        let Some(session) = &self.tun_session else {
            // No TUN device — just sleep for the timeout duration.
            if let Some(t) = timeout {
                std::thread::sleep(t);
            }
            return;
        };
        let ms = timeout.map_or(windows_sys::Win32::System::Threading::INFINITE, |t| {
            let ms = t.as_millis();
            u32::try_from(ms).unwrap_or(u32::MAX)
        });
        // Safety: read_wait_event() returns a valid HANDLE from WintunGetReadWaitEvent.
        unsafe {
            Win32_Threading::WaitForSingleObject(session.read_wait_event(), ms);
        }
    }

    /// Wait for data on the network transport (TUN or IPC), or until
    /// `timeout` expires.
    pub fn wait_on_network(&self, timeout: Option<Duration>) {
        // TUN path — delegate to existing wait_on_tun.
        if self.tun_session.is_some() {
            return self.wait_on_tun(timeout);
        }

        // IPC path — poll the broker stream for POLLIN.
        if let Some(stream_lock) = self.ipc_stream.get() {
            if self.ipc_dead.load(core::sync::atomic::Ordering::Relaxed) {
                if let Some(t) = timeout {
                    std::thread::sleep(t);
                }
                return;
            }
            let raw_socket = stream_lock.lock().unwrap().raw_socket();

            #[repr(C)]
            struct WsaPollFd {
                fd: usize,
                events: i16,
                revents: i16,
            }
            #[link(name = "ws2_32")]
            unsafe extern "system" {
                fn WSAPoll(fds: *mut WsaPollFd, nfds: u32, timeout: i32) -> i32;
            }
            let timeout_ms = match timeout {
                Some(t) => {
                    let ms = t.as_millis();
                    if ms == 0 && !t.is_zero() {
                        1
                    } else {
                        i32::try_from(ms).unwrap_or(i32::MAX)
                    }
                }
                None => -1,
            };
            // WinSock WSAPoll bitmask values (different from POSIX!):
            //   POLLRDNORM = 0x0100, POLLIN = 0x0300, POLLOUT/POLLWRNORM = 0x0010
            //   POLLERR = 0x0001, POLLHUP = 0x0002, POLLNVAL = 0x0004
            const WS_POLLIN: i16 = 0x0300;
            const WS_POLLERR: i16 = 0x0001;
            const WS_POLLHUP: i16 = 0x0002;
            let mut pfd = WsaPollFd {
                fd: raw_socket,
                events: WS_POLLIN,
                revents: 0,
            };
            unsafe {
                WSAPoll(&mut pfd, 1, timeout_ms);
            }
            // If the socket reported error or hangup, mark the transport dead
            // so the worker transitions to the sleep path.
            if pfd.revents & (WS_POLLERR | WS_POLLHUP) != 0 {
                self.ipc_dead
                    .store(true, core::sync::atomic::Ordering::Relaxed);
            }
            return;
        }

        // No transport — sleep.
        if let Some(t) = timeout {
            std::thread::sleep(t);
        }
    }
}

impl litebox::platform::RawMessageProvider for WindowsUserland {}

impl litebox::platform::Provider for WindowsUserland {}

impl litebox::platform::SignalProvider for WindowsUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let bits = get_tls_ptr().map_or(0, |p| {
            unsafe { &*p }
                .pending_host_signals
                .swap(0, Ordering::SeqCst)
        });
        let sigs = litebox_common_linux::signal::SigSet::from_u64(u64::from(bits));
        for signal in sigs {
            f(signal);
        }
    }
}

impl litebox::platform::AddressSpaceProvider for WindowsUserland {
    type AddressSpaceId = u32;

    // The Windows exception dispatcher, allocator metadata, and globals all
    // live in the shared address space. A CoW page fault inside the handler
    // would be fatal, so we must eagerly snapshot all writable pages.
    const EAGER_COW_FOR_VFORK: bool = true;

    fn create_address_space(
        &self,
    ) -> Result<Self::AddressSpaceId, litebox::platform::address_space::AddressSpaceError> {
        let mut partitions = self.partitions.lock().unwrap();
        let prefer_slot0 = self
            .prefer_slot0_for_first_address_space
            .swap(false, Ordering::Relaxed);
        if prefer_slot0 && !partitions.is_allocated(0) {
            let id = partitions
                .allocate()
                .ok_or(litebox::platform::address_space::AddressSpaceError::NoSpace)?;
            debug_assert_eq!(id, 0, "slot 0 should be the first allocated slot");
            return Ok(id);
        }
        // Try to find a clean VA partition first (no host allocations).
        // This avoids fragmentation conflicts when the guest does its own
        // memory management (e.g., ntdll heap init, DLL loading).
        if let Some(id) = partitions.allocate_probed(is_va_range_clean) {
            return Ok(id);
        }
        // Fallback: use any available slot even if host-contaminated.
        let id = partitions
            .allocate()
            .ok_or(litebox::platform::address_space::AddressSpaceError::NoSpace)?;
        Ok(id)
    }

    fn destroy_address_space(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<(), litebox::platform::address_space::AddressSpaceError> {
        if !self.partitions.lock().unwrap().deallocate(id) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        Ok(())
    }

    fn fork_address_space(
        &self,
        parent: Self::AddressSpaceId,
    ) -> Result<
        litebox::platform::address_space::ForkedAddressSpace<Self::AddressSpaceId>,
        litebox::platform::address_space::AddressSpaceError,
    > {
        // Validate parent and allocate child under a single lock to avoid
        // TOCTOU races (the Linux impl drops and re-acquires the lock).
        let mut partitions = self.partitions.lock().unwrap();
        if !partitions.is_allocated(parent) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        let child = partitions
            .allocate_probed(is_va_range_clean)
            .ok_or(litebox::platform::address_space::AddressSpaceError::NoSpace)?;
        Ok(litebox::platform::address_space::ForkedAddressSpace::SharedWithParent(child))
    }

    fn activate_address_space(
        &self,
        _id: Self::AddressSpaceId,
    ) -> Result<(), litebox::platform::address_space::AddressSpaceError> {
        // No-op on userland — all processes share the host address space.
        Ok(())
    }

    fn address_space_range(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<core::ops::Range<usize>, litebox::platform::address_space::AddressSpaceError> {
        let partitions = self.partitions.lock().unwrap();
        if !partitions.is_allocated(id) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        Ok(partitions.range_of(id))
    }
}

/// Ensures the module-wide TLS slot index ([`TLS_INDEX`]) has been allocated.
///
/// This must be called before any code that reads `TLS_INDEX`. Both
/// [`run_thread`] (guest threads) and [`run_test_thread`](WindowsUserland::run_test_thread)
/// (test threads) go through here.
fn ensure_tls_index() {
    // Allocate a TLS slot for this module if not already done. This is used as
    // a place to store data across calls to the guest, since all the registers
    // are used by the guest and will be clobbered.
    //
    // We use this instead of native TLS because accesses are easier from
    // assembly. In particular, finding the module's TLS base requires extra
    // registers and/or clobbering flags, whereas we can get the value of a
    // TLS slot with only one register and no changes to flags.
    static REGISTER_KEY: std::sync::Once = const { std::sync::Once::new() };
    REGISTER_KEY.call_once(|| {
        let index = unsafe { windows_sys::Win32::System::Threading::TlsAlloc() };
        assert!(
            index < 64,
            "no non-extended TLS slots available: {index:#x}"
        );
        TLS_INDEX.store(index, Ordering::Relaxed);
    });
}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread(
    shim: impl litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &mut litebox_common_linux::ExecutionContext,
) {
    ensure_tls_index();
    run_thread_inner(&shim, ctx);
}

/// Run a guest thread using a reference to the shim.
///
/// Unlike [`run_thread`], this version takes a reference instead of
/// ownership, so the caller retains access to the shim after the thread
/// terminates. This is useful when the shim carries state that must be
/// read after execution (e.g., [`NtShimEntrypoints::exit_code`]).
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::ExecutionContext)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
{
    ensure_tls_index();
    run_thread_inner(shim, ctx);
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &mut litebox_common_linux::ExecutionContext,
) {
    let tls_state = TlsState::new();
    tls_state
        .guest_context_top
        .set(core::ptr::from_mut(&mut ctx.regs).wrapping_add(1));

    let mut thread_ctx = ThreadContext {
        shim,
        ctx,
        tls: &tls_state,
    };
    let signal_process_key = shim
        .process_id()
        .zip(shim.signal_target_scope())
        .map(|(process_id, scope)| SignalProcessKey { scope, process_id });
    ThreadHandle::run_with_handle(&tls_state, signal_process_key, || unsafe {
        run_thread_arch(&mut thread_ctx, &tls_state);
    });
    // Clear guest TEB base so a subsequent Linux-mode guest on this thread
    // does not inherit a stale Windows TEB address.
    THREAD_FS_BASE.set(0);
    THREAD_GUEST_VA_START.set(0);
    THREAD_GUEST_VA_END.set(0);
    shim.thread_terminated();
}

static TLS_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);

struct TlsState {
    host_sp: Cell<*mut u128>,
    host_bp: Cell<*mut u128>,
    guest_context_top: Cell<*mut litebox_common_linux::PtRegs>,
    scratch: Cell<usize>,
    /// Second scratch slot used by the syscall callback to preserve the
    /// syscall number (rax) across fxsave64/xsave64 which clobbers rax.
    scratch2: Cell<usize>,
    is_in_guest: Cell<bool>,
    interrupt: Cell<bool>,
    /// Guest TEB base address. When non-zero, switch_to_guest restores this
    /// via wrfsbase before entering the guest (NT-mode guests need FS → TEB).
    guest_teb_base: Cell<u64>,
    /// Guest VA bounds for the current thread's address space.
    guest_va_start: Cell<usize>,
    guest_va_end: Cell<usize>,
    #[allow(dead_code)]
    continue_context:
        Box<std::cell::UnsafeCell<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>>,
    /// Bitmask of pending host-originated signals for this thread.
    pending_host_signals: AtomicU32,
    /// Pointer to the `Waker` currently being waited on, or null if not
    /// waiting.
    waiting_waker: std::sync::atomic::AtomicPtr<litebox::event::wait::Waker<WindowsUserland>>,
    /// Non-zero if XSAVE is supported and should be used instead of FXSAVE.
    xsave_enabled: Cell<u8>,
    /// Low 32 bits of the XSAVE feature mask (x87=bit0, SSE=bit1, AVX=bit2).
    xsave_mask_lo: Cell<u32>,
    /// High 32 bits of the XSAVE feature mask (always 0 for now).
    xsave_mask_hi: Cell<u32>,
    /// If non-zero, single-step that many guest instructions and then dump.
    post_continue_step_budget: Cell<u32>,
    trace_cursor: Cell<u32>,
    trace_entries: [Cell<TransitionTraceEntry>; TRANSITION_TRACE_LEN],
}

impl TlsState {
    /// Creates a new `TlsState` with all fields zeroed / defaulted.
    ///
    /// Copies `THREAD_FS_BASE` into the struct so the switch_to_guest asm
    /// can read it without going through the Windows thread_local! API.
    /// Detects XSAVE support via CPUID for conditional FP save/restore.
    fn new() -> Self {
        let (enabled, mask_lo, mask_hi) = detect_xsave_support();
        Self {
            host_sp: Cell::new(core::ptr::null_mut()),
            host_bp: Cell::new(core::ptr::null_mut()),
            guest_context_top: core::ptr::null_mut::<litebox_common_linux::PtRegs>().into(),
            scratch: 0.into(),
            scratch2: 0.into(),
            is_in_guest: false.into(),
            interrupt: false.into(),
            guest_teb_base: Cell::new(THREAD_FS_BASE.get() as u64),
            guest_va_start: Cell::new(THREAD_GUEST_VA_START.get()),
            guest_va_end: Cell::new(THREAD_GUEST_VA_END.get()),
            continue_context: Box::default(),
            pending_host_signals: AtomicU32::new(0),
            waiting_waker: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
            xsave_enabled: Cell::new(enabled),
            xsave_mask_lo: Cell::new(mask_lo),
            xsave_mask_hi: Cell::new(mask_hi),
            post_continue_step_budget: Cell::new(0),
            trace_cursor: Cell::new(0),
            trace_entries: [const { Cell::new(TransitionTraceEntry::EMPTY) }; TRANSITION_TRACE_LEN],
        }
    }

    fn guest_va_contains(&self, addr: usize) -> bool {
        let start = self.guest_va_start.get();
        let end = self.guest_va_end.get();
        start != 0 && start < end && addr >= start && addr < end
    }

    fn trace_transition(
        &self,
        kind: TransitionTraceKind,
        detail: u32,
        rip: u64,
        rsp: u64,
        r11: u64,
        rflags: u64,
    ) {
        self.trace_transition_with_metadata(
            kind,
            detail,
            rip,
            rsp,
            r11,
            rflags,
            read_mxcsr(),
            unsafe { Win32_Threading::GetCurrentThreadId() },
        );
    }

    fn trace_transition_with_metadata(
        &self,
        kind: TransitionTraceKind,
        detail: u32,
        rip: u64,
        rsp: u64,
        r11: u64,
        rflags: u64,
        mxcsr: u32,
        thread_id: u32,
    ) {
        let seq = self.trace_cursor.get().wrapping_add(1);
        self.trace_cursor.set(seq);
        let idx = (seq as usize).wrapping_sub(1) % TRANSITION_TRACE_LEN;
        self.trace_entries[idx].set(TransitionTraceEntry {
            seq,
            kind: kind.as_u8(),
            _pad: [0; 3],
            detail,
            rip,
            rsp,
            r11,
            rflags,
            mxcsr,
            thread_id,
        });
    }

    fn dump_transition_trace(&self, label: &str) {
        use core::fmt::Write;

        let cursor = self.trace_cursor.get();
        if cursor == 0 {
            eprintln!("[{label}] no transition trace captured");
            return;
        }

        let count = cursor.min(TRANSITION_TRACE_LEN as u32) as usize;
        let start = cursor.saturating_sub(count as u32) + 1;
        let mut msg = alloc::format!("[{label}] last {count} transition(s):\n");
        for seq in start..=cursor {
            let idx = (seq as usize).wrapping_sub(1) % TRANSITION_TRACE_LEN;
            let entry = self.trace_entries[idx].get();
            if entry.seq != seq {
                continue;
            }
            if entry.kind == TransitionTraceKind::SingleStep.as_u8() {
                let _ = writeln!(
                    msg,
                    "  #{:05} tid={} kind={} remaining={} rip=0x{:X} rsp=0x{:X} fault_scratch=0x{:X} guest_teb=0x{:X} mxcsr=0x{:08X}",
                    entry.seq,
                    entry.thread_id,
                    TransitionTraceKind::name(entry.kind),
                    entry.detail,
                    entry.rip,
                    entry.rsp,
                    entry.r11,
                    entry.rflags,
                    entry.mxcsr,
                );
                continue;
            }
            let _ = writeln!(
                msg,
                "  #{:05} tid={} kind={} {} rip=0x{:X} rsp=0x{:X} r11=0x{:X} rflags=0x{:X} mxcsr=0x{:08X}",
                entry.seq,
                entry.thread_id,
                TransitionTraceKind::name(entry.kind),
                format_transition_detail(entry.kind, entry.detail),
                entry.rip,
                entry.rsp,
                entry.r11,
                entry.rflags,
                entry.mxcsr,
            );
        }
        eprintln!("{msg}");
    }
}

/// x87 | SSE | AVX — the state components we save/restore for the guest.
const GUEST_XSAVE_MASK: u64 = 0x7;

/// Detect XSAVE support and return (enabled, mask_lo, mask_hi).
fn detect_xsave_support() -> (u8, u32, u32) {
    use core::arch::x86_64::{__cpuid, _xgetbv};

    // CPUID.01H:ECX.XSAVE[bit 26] and OSXSAVE[bit 27] gate XSAVE/XGETBV.
    // CPUID is always safe on x86_64.
    let leaf1 = __cpuid(1);
    let has_xsave = (leaf1.ecx & (1 << 26)) != 0;
    let has_osxsave = (leaf1.ecx & (1 << 27)) != 0;
    if !(has_xsave && has_osxsave) {
        return (0, 0, 0);
    }

    // SAFETY: CPUID confirmed XSAVE and OSXSAVE — XGETBV(0) is valid.
    let xcr0 = unsafe { _xgetbv(0) };
    let mask = xcr0 & GUEST_XSAVE_MASK;
    // We need at least x87+SSE (bits 0,1) to use xsave/xrstor.
    if (mask & 0x3) != 0x3 {
        return (0, 0, 0);
    }
    (1, mask as u32, (mask >> 32) as u32)
}

/// Stores `tls` in the current thread's Windows TLS slot.
///
/// # Safety
///
/// The caller must ensure `tls` remains valid for the duration of its use.
unsafe fn install_tls(tls: &TlsState) {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    unsafe {
        windows_sys::Win32::System::Threading::TlsSetValue(
            tls_index,
            core::ptr::from_ref(tls).cast(),
        );
    }
}

/// Clears the current thread's Windows TLS slot.
fn uninstall_tls() {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    unsafe { windows_sys::Win32::System::Threading::TlsSetValue(tls_index, core::ptr::null()) };
}

fn get_tls_ptr() -> Option<*const TlsState> {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    if tls_index == u32::MAX {
        return None;
    }
    let ptr =
        unsafe { windows_sys::Win32::System::Threading::TlsGetValue(tls_index).cast::<TlsState>() };
    if ptr.is_null() {
        return None;
    }
    Some(ptr)
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
unsafe extern "C-unwind" fn run_thread_arch(thread_ctx: &mut ThreadContext, tls_state: &TlsState) {
    core::arch::naked_asm!(
    "
    .seh_proc run_thread
    // Push all non-volatiles
    push rbp
    .seh_pushreg rbp
    mov rbp, rsp
    .seh_setframe rbp, 0
    push rbx
    .seh_pushreg rbx
    push rdi
    .seh_pushreg rdi
    push rsi
    .seh_pushreg rsi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 168 // align + space for xmm6-xmm15
    .seh_stackalloc 168
    movdqa [rsp + 0*16], xmm6
    .seh_savexmm xmm6, 0*16
    movdqa [rsp + 1*16], xmm7
    .seh_savexmm xmm7, 1*16
    movdqa [rsp + 2*16], xmm8
    .seh_savexmm xmm8, 2*16
    movdqa [rsp + 3*16], xmm9
    .seh_savexmm xmm9, 3*16
    movdqa [rsp + 4*16], xmm10
    .seh_savexmm xmm10, 4*16
    movdqa [rsp + 5*16], xmm11
    .seh_savexmm xmm11, 5*16
    movdqa [rsp + 6*16], xmm12
    .seh_savexmm xmm12, 6*16
    movdqa [rsp + 7*16], xmm13
    .seh_savexmm xmm13, 7*16
    movdqa [rsp + 8*16], xmm14
    .seh_savexmm xmm14, 8*16
    movdqa [rsp + 9*16], xmm15
    .seh_savexmm xmm15, 9*16
    .seh_endprologue

    // Offset into the TEB (gs segment) where TLS slots are stored.
    .equ TEB_TLS_SLOTS_OFFSET, 5248

    push    rcx // Alignment
    push    rcx // Save thread_ctx

    // Save the host rsp and rbp into the TLS state.
    mov     QWORD PTR [rdx + {HOST_SP}], rsp
    mov     QWORD PTR [rdx + {HOST_BP}], rbp

    call {init_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // GS is always host TEB now — no guest GS swap needed.
    // The register context is the guest context with the return address in rcx.
    .globl  syscall_callback
syscall_callback:

    // --- GS is host.  Clear is_in_guest and proceed. ---
    // Get the TLS state from the TLS slot and clear the in-guest flag.
    mov     r11d, DWORD PTR [rip + {TLS_INDEX}]
    mov     r11, QWORD PTR gs:[r11 * 8 + TEB_TLS_SLOTS_OFFSET]
    mov     BYTE PTR [r11 + {IS_IN_GUEST}], 0
    mov     QWORD PTR [r11 + {SCRATCH2}], rax
    mov     QWORD PTR [r11 + {SCRATCH}], rsp
    jmp     .Lsyscall_callback_common

    .globl  syscall_callback_redzone
syscall_callback_redzone:
    // Get the TLS state from the TLS slot and clear the in-guest flag.
    mov     r11d, DWORD PTR [rip + {TLS_INDEX}]
    mov     r11, QWORD PTR gs:[r11 * 8 + TEB_TLS_SLOTS_OFFSET]
    mov     BYTE PTR [r11 + {IS_IN_GUEST}], 0
    // The rewriter trampoline lowered RSP by 128 bytes to protect the SysV
    // red zone. Recover the architectural guest stack pointer before saving
    // pt_regs so normal `ret` instructions still see the original return
    // address after the syscall resumes.
    mov     QWORD PTR [r11 + {SCRATCH2}], rax
    lea     rax, [rsp + 128]
    mov     QWORD PTR [r11 + {SCRATCH}], rax

.Lsyscall_callback_common:
    // Set rsp to the top of the guest context.
    mov     rsp, QWORD PTR [r11 + {GUEST_CONTEXT_TOP}]

    // Save guest FP/SIMD state. fp_regs is at GUEST_CONTEXT_TOP + FP_REGS_PAD
    // (padding between end of PtRegs and start of 64-byte-aligned FpRegs).
    // Preserve rax (syscall number) in scratch2 because xsave/fxsave uses eax:edx.
    lea     rax, [rsp + {FP_REGS_PAD}]
    cmp     BYTE PTR [r11 + {XSAVE_ENABLED}], 0
    je      .Lsyscall_fp_save_fxsave
    // xsave64 path: need eax:edx = mask, memory operand = buffer address.
    // Stash guest rcx and rdx in PtRegs slots (will be overwritten by pushes).
    mov     QWORD PTR [rsp], rcx              // temp stash at PtRegs[r15] slot
    mov     QWORD PTR [rsp + 8], rdx          // temp stash at PtRegs[r14] slot
    mov     rcx, rax                           // rcx = buffer ptr
    mov     eax, DWORD PTR [r11 + {XSAVE_MASK_LO}]
    mov     edx, DWORD PTR [r11 + {XSAVE_MASK_HI}]
    xsave64 [rcx]
    mov     rcx, QWORD PTR [rsp]              // restore guest rcx
    mov     rdx, QWORD PTR [rsp + 8]          // restore guest rdx
    jmp     .Lsyscall_fp_save_done
.Lsyscall_fp_save_fxsave:
    fxsave64 [rax]
.Lsyscall_fp_save_done:
    // Sanitize MXCSR for host Rust code (guest may have set denormals-are-zero
    // or flush-to-zero bits that could cause unexpected behavior in host math).
    ldmxcsr DWORD PTR [rip + DEFAULT_MXCSR]
    // Restore syscall number from scratch2.
    mov     rax, QWORD PTR [r11 + {SCRATCH2}]
    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    QWORD PTR [r11 + {SCRATCH}] // pt_regs->sp
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
    push    r12
    push    r13
    push    r14
    push    r15

    /// Reestablish the stack and frame pointers.
    mov     rsp, [r11 + {HOST_SP}]
    mov     rbp, [r11 + {HOST_BP}]

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    sub  rsp, 0x20             // shadow space (Windows x64 ABI)
    call {syscall_handler}
    add  rsp, 0x20
    jmp .Ldone

exception_callback:
    // Handle the exception. The stack and frame pointers are already restored,
    // and the guest context is up to date. rcx contains a pointer to the
    // guest pt_regs, and rdx contains a pointer to the exception record.
    // GS is always host TEB now — no guest GS swap needed.
    // Sanitize MXCSR: the OS restored the guest's FP state (including MXCSR)
    // when continuing from the VEH handler. Guest may have set FTZ/DAZ bits
    // that would corrupt host SSE operations (memcpy, comparisons, etc.).
    ldmxcsr DWORD PTR [rip + DEFAULT_MXCSR]
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    sub  rsp, 0x20             // shadow space (Windows x64 ABI)
    call {exception_handler}
    add  rsp, 0x20
    jmp .Ldone

interrupt_callback:
    // GS is always host TEB now — no guest GS swap needed.
    // Sanitize MXCSR: SetThreadContext restored the guest's FP state
    // (including MXCSR) from GetThreadContext. Guest may have set FTZ/DAZ
    // bits that would corrupt host SSE operations.
    ldmxcsr DWORD PTR [rip + DEFAULT_MXCSR]
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    sub  rsp, 0x20             // shadow space (Windows x64 ABI)
    call {interrupt_handler}
    add  rsp, 0x20
    jmp .Ldone

.Ldone:
    // Restore non-volatile registers and return.
    lea  rsp, [rbp - (168 + 56)]
    movdqa xmm6, [rsp + 0*16]
    movdqa xmm7, [rsp + 1*16]
    movdqa xmm8, [rsp + 2*16]
    movdqa xmm9, [rsp + 3*16]
    movdqa xmm10, [rsp + 4*16]
    movdqa xmm11, [rsp + 5*16]
    movdqa xmm12, [rsp + 6*16]
    movdqa xmm13, [rsp + 7*16]
    movdqa xmm14, [rsp + 8*16]
    movdqa xmm15, [rsp + 9*16]
    add rsp, 168 // 10 * 16 + 8 (for stack alignment)
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rdi
    pop  rbx
    pop  rbp
    ret
    .seh_endproc

    // Read-only data for MXCSR sanitization (default value with all exceptions
    // masked, round-to-nearest).
    .section .rdata, \"dr\"
    .balign 4
DEFAULT_MXCSR:
    .long 0x1F80
    .text
    ",
    init_handler = sym init_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    TLS_INDEX = sym TLS_INDEX,
    HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
    HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
    GUEST_CONTEXT_TOP = const core::mem::offset_of!(TlsState, guest_context_top),
    SCRATCH = const core::mem::offset_of!(TlsState, scratch),
    SCRATCH2 = const core::mem::offset_of!(TlsState, scratch2),
    IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
    XSAVE_ENABLED = const core::mem::offset_of!(TlsState, xsave_enabled),
    XSAVE_MASK_LO = const core::mem::offset_of!(TlsState, xsave_mask_lo),
    XSAVE_MASK_HI = const core::mem::offset_of!(TlsState, xsave_mask_hi),
    // Padding between end of PtRegs and start of FpRegs in ExecutionContext.
    // FpRegs is align(64); PtRegs is 168 bytes; next 64-byte boundary is 192.
    FP_REGS_PAD = const {
        core::mem::offset_of!(litebox_common_linux::ExecutionContext, fp_regs)
            - core::mem::size_of::<litebox_common_linux::PtRegs>()
    },
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
///
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::ExecutionContext) -> ! {
    unsafe {
        /// Restores the full guest register state and jumps to the guest RIP
        /// entirely in user-mode — no kernel round-trip.
        ///
        /// GS always points to the host TEB (the kernel restores it on
        /// context switches). FS is set to the guest TEB via wrfsbase before
        /// GP registers are loaded; kernel clobbers (FS→0) are caught by the
        /// VEH handler and repaired from `THREAD_FS_BASE`.
        ///
        /// The guest entry sequence:
        /// 1. Restore guest FP/SIMD state.
        /// 2. `wrfsbase` guest TEB (if NT-mode).
        /// 3. Pre-stage guest_rip at `(guest_rsp - 8)`.
        /// 4. Pop ALL GP registers.
        /// 5. `popfq` + `pop rsp` to restore EFLAGS and RSP.
        /// 6. `lea rsp, [rsp - 8]; ret` to jump to guest RIP.
        #[unsafe(naked)]
        extern "C" fn switch_to_guest_sysret(ctx: &litebox_common_linux::ExecutionContext) -> ! {
            core::arch::naked_asm!(
                // === switch_to_guest_start..switch_to_guest_end ===
                // This range is checked by ThreadHandle::interrupt() to detect
                // when a thread is in the process of entering guest code. If
                // interrupted here, the thread is redirected to interrupt_callback
                // and re-enters switch_to_guest later. The ExecutionContext is
                // not modified below, so re-entry is safe (the pre-staging write
                // to the guest stack is idempotent).
                "switch_to_guest_start:",
                // Set is_in_guest = true FIRST, then check the interrupt flag.
                // This mirrors the Linux platform: any ThreadHandle::interrupt()
                // that arrives after this point will either see is_in_guest=true
                // and redirect via SetThreadContext, or the deferred check below
                // will catch the flag before we enter the guest.
                "mov     r11d, DWORD PTR [rip + {TLS_INDEX}]",
                "mov     r11, QWORD PTR gs:[r11 * 8 + 5248]", // TEB_TLS_SLOTS → TlsState*
                "mov     BYTE PTR [r11 + {IS_IN_GUEST}], 1",
                // Check for a pending interrupt BEFORE restoring guest FP state.
                // If the flag is set, divert to interrupt_callback immediately
                // while FP state is still host (XMM6-15 callee-saved values are
                // intact) and the host stack is easily recoverable.
                "cmp     BYTE PTR [r11 + {INTERRUPT}], 0",
                "je      .Lno_pending_interrupt",
                "mov     rsp, QWORD PTR [r11 + {HOST_SP}]",
                "mov     rbp, QWORD PTR [r11 + {HOST_BP}]",
                "jmp     {interrupt_callback}",
                ".Lno_pending_interrupt:",
                // Restore guest FP/SIMD state before touching any guest registers.
                // rcx = ptr to ExecutionContext; fp_regs is at offset FP_REGS_OFFSET.
                "cmp     BYTE PTR [r11 + {XSAVE_ENABLED}], 0",
                "je      .Lguest_fp_restore_fxrstor",
                // xrstor64 path: need eax:edx = mask.
                "mov     eax, DWORD PTR [r11 + {XSAVE_MASK_LO}]",
                "mov     edx, DWORD PTR [r11 + {XSAVE_MASK_HI}]",
                "xrstor64 [rcx + {FP_REGS_OFFSET}]",
                "jmp     .Lguest_fp_restore_done",
                ".Lguest_fp_restore_fxrstor:",
                "fxrstor64 [rcx + {FP_REGS_OFFSET}]",
                ".Lguest_fp_restore_done:",
                // Read guest_teb_base from TlsState. If zero (Linux guest),
                // skip the wrfsbase.
                "mov     r11, QWORD PTR [r11 + {GUEST_TEB_BASE}]",
                "test    r11, r11",
                "jz      2f",
                "wrfsbase r11",            // FS = guest TEB
                "2:",
                // Re-read TlsState pointer for remaining field accesses.
                "mov     r10d, DWORD PTR [rip + {TLS_INDEX}]",
                "mov     r10, QWORD PTR gs:[r10 * 8 + 5248]",
                // If a post-continue single-step probe is armed, set TF in the
                // saved guest EFLAGS now so the first trap happens after the
                // first real guest instruction, not inside this transition stub.
                "cmp     DWORD PTR [r10 + {POST_CONTINUE_STEP_BUDGET}], 0",
                "je      4f",
                "or      QWORD PTR [rcx + {PT_EFLAGS}], 0x100",
                "4:",
                // Pre-stage: write guest_rip below guest_rsp.
                // Layout: [guest_rip @ rsp-8]
                // This does NOT modify the ExecutionContext, so it is idempotent
                // and safe if an interrupt causes re-entry.
                "mov     rax, QWORD PTR [rcx + {PT_RSP}]",
                "mov     r11, QWORD PTR [rcx + {PT_RIP}]",
                "mov     QWORD PTR [rax - 8], r11",           // guest_rip
                // Load all GP registers from the guest context structure.
                // GS is still host TEB throughout — immune to kernel preemption.
                // FS is guest TEB (or 0 for Linux guests, repaired by VEH).
                "mov rsp, rcx",
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
                "pop rcx",       // guest's actual RCX
                "pop rdx",
                "pop rsi",
                "pop rdi",
                "add rsp, 24",   // skip orig_rax + rip + cs
                "popfq",
                "pop rsp",                         // rsp = guest_rsp
                // Jump to guest code via the pre-staged RIP.
                "lea rsp, QWORD PTR [rsp - 8]",   // rsp → [guest_rip]
                "ret",                             // pop guest_rip, rsp = guest_rsp
                "switch_to_guest_end:",
                FP_REGS_OFFSET = const core::mem::offset_of!(litebox_common_linux::ExecutionContext, fp_regs),
                TLS_INDEX = sym TLS_INDEX,
                GUEST_TEB_BASE = const core::mem::offset_of!(TlsState, guest_teb_base),
                IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
                INTERRUPT = const core::mem::offset_of!(TlsState, interrupt),
                HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
                HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
                interrupt_callback = sym interrupt_callback,
                POST_CONTINUE_STEP_BUDGET =
                    const core::mem::offset_of!(TlsState, post_continue_step_budget),
                XSAVE_ENABLED = const core::mem::offset_of!(TlsState, xsave_enabled),
                XSAVE_MASK_LO = const core::mem::offset_of!(TlsState, xsave_mask_lo),
                XSAVE_MASK_HI = const core::mem::offset_of!(TlsState, xsave_mask_hi),
                PT_EFLAGS = const core::mem::offset_of!(litebox_common_linux::PtRegs, eflags),
                PT_RIP = const core::mem::offset_of!(litebox_common_linux::PtRegs, rip),
                PT_RSP = const core::mem::offset_of!(litebox_common_linux::PtRegs, rsp),
            );
        }

        let tls = &*get_tls_ptr().expect("TLS not initialized");
        assert!(!tls.is_in_guest.get());

        // Restore fsbase for the guest.
        WindowsUserland::restore_thread_fs_base();

        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        {
            static SWITCH_TRACE_COUNT: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let count = SWITCH_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
            if count < 32 || count.is_power_of_two() {
                trace_debugln!(
                    "[switch-guest] count={} rip=0x{:X} rsp=0x{:X} rax=0x{:X} rcx=0x{:X} interrupt={} pending_host_signals={:#x}",
                    count,
                    ctx.rip,
                    ctx.rsp,
                    ctx.rax,
                    ctx.rcx,
                    tls.interrupt.get(),
                    tls.pending_host_signals.load(Ordering::Relaxed),
                );
            }
            // Validate guest RSP is writable before switching.
            #[repr(C)]
            struct MemoryBasicInformation {
                base_address: u64,
                allocation_base: u64,
                allocation_protect: u32,
                _pad1: u32,
                region_size: u64,
                state: u32,
                protect: u32,
                type_: u32,
                _pad2: u32,
            }
            unsafe extern "system" {
                fn VirtualQuery(
                    addr: *const u8,
                    info: *mut MemoryBasicInformation,
                    len: usize,
                ) -> usize;
            }
            let mut mbi = core::mem::zeroed::<MemoryBasicInformation>();
            let ret = VirtualQuery(
                ctx.rsp as *const u8,
                &mut mbi,
                core::mem::size_of::<MemoryBasicInformation>(),
            );
            if ret == 0 {
                trace_debugln!(
                    "[switch-guest] WARNING: VirtualQuery(RSP=0x{:X}) FAILED",
                    ctx.rsp
                );
            } else {
                let writable = (mbi.protect & 0x04) != 0  // PAGE_READWRITE
                || (mbi.protect & 0x40) != 0  // PAGE_EXECUTE_READWRITE
                || (mbi.protect & 0x08) != 0; // PAGE_WRITECOPY
                if mbi.state != 0x1000 || !writable {
                    trace_debugln!(
                        "[switch-guest] WARNING: RSP=0x{:X} state=0x{:X} protect=0x{:X} NOT WRITABLE",
                        ctx.rsp,
                        mbi.state,
                        mbi.protect,
                    );
                }
            }
        }
        tls.trace_transition(
            TransitionTraceKind::SwitchToGuest,
            0,
            ctx.rip as u64,
            ctx.rsp as u64,
            ctx.r11 as u64,
            ctx.eflags as u64,
        );
        // is_in_guest is now set inside the asm (after FP restore, before GP
        // register restore) so VEH cannot misclassify a host fault as guest.
        switch_to_guest_sysret(ctx)
    }
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::ExecutionContext>,
    >,
    mut ctx: litebox_common_linux::ExecutionContext,
) {
    // Wrap init() in catch_unwind so a panic during initialization is
    // handled gracefully rather than propagating to the thread boundary.
    let shim = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| init_thread.init())) {
        Ok(shim) => shim,
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown".to_string()
            };
            eprintln!("[platform] child thread panicked during init: {msg}");
            return;
        }
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_thread_inner(shim.as_ref(), &mut ctx);
    }));
    if let Err(e) = result {
        let msg = if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown".to_string()
        };
        eprintln!("[platform] child thread panicked: {msg}");
        // Ensure the shim knows this thread terminated so that waiters
        // (e.g., main thread in WaitForMultipleObjects) are unblocked.
        shim.thread_terminated();
    }
}

impl litebox::platform::ThreadProvider for WindowsUserland {
    type ExecutionContext = litebox_common_linux::ExecutionContext;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::ExecutionContext>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        // Use 8 MiB stack (matching Linux default) to avoid overflow from
        // deeply-nested shim call chains. Windows default is only 1 MiB.
        let _handle = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || thread_start(init_thread, ctx))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        CURRENT_THREAD_HANDLE.with_borrow(|current| {
            current
                .clone()
                .expect("current thread is not managed by LiteBox")
        })
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        CURRENT_THREAD_HANDLE.with_borrow(|current| {
            thread.interrupt(current.as_ref());
        });
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        // Ensure the module-wide TLS slot is allocated.
        ensure_tls_index();
        let tls = TlsState::new();
        ThreadHandle::run_with_handle(&tls, None, f)
    }
}

impl litebox::platform::TimerProvider for WindowsUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        let target = CURRENT_THREAD_HANDLE.with_borrow(|current| {
            let handle = current
                .as_ref()
                .expect("timers require a managed guest thread")
                .clone();
            match handle.process_key() {
                Some(process_key) => SignalTarget::Process(process_key),
                None => SignalTarget::Thread(handle),
            }
        });
        let ctx = Box::new(TimerCallbackContext { signal, target });

        // Create a threadpool timer with the callback registered up-front.
        // The callback fires whenever the timer is armed via
        // `SetThreadpoolTimer` and the due time elapses.
        //
        // Safety: We pass a raw pointer to `ctx` which is heap-allocated via
        // `Box` and lives as long as the `TimerHandle`. The `Drop` impl
        // cancels and waits for all in-flight callbacks before the `Box` is
        // dropped, so the pointer remains valid for every callback invocation.
        let tp_timer = unsafe {
            Win32_Threading::CreateThreadpoolTimer(
                Some(threadpool_timer_callback),
                &raw const *ctx as *mut c_void,
                std::ptr::null(),
            )
        };
        assert!(
            tp_timer != 0,
            "CreateThreadpoolTimer failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(TimerHandle {
            tp_timer,
            _ctx: ctx,
        })
    }
}

pub struct TimerHandle {
    tp_timer: Win32_Threading::PTP_TIMER,
    /// Prevent the context from being dropped while the timer is alive.
    /// The raw pointer passed to the threadpool callback points into this box.
    _ctx: Box<TimerCallbackContext>,
}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        // Cancel any pending callback, wait for in-flight callbacks to
        // complete, then close the threadpool timer.
        //
        // After this sequence completes the callback will never run again, so
        // it is safe to let `self.ctx` (the `Box`) drop normally.
        unsafe {
            Win32_Threading::SetThreadpoolTimer(self.tp_timer, std::ptr::null(), 0, 0);
            Win32_Threading::WaitForThreadpoolTimerCallbacks(self.tp_timer, 1);
            Win32_Threading::CloseThreadpoolTimer(self.tp_timer);
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: core::time::Duration) {
        if duration.is_zero() {
            // A zero duration cancels the timer without firing.
            // Passing NULL as the due-time pointer tells Windows to cancel
            // the pending callback.
            unsafe {
                Win32_Threading::SetThreadpoolTimer(self.tp_timer, std::ptr::null(), 0, 0);
            }
            return;
        }

        // Due time is in 100 ns intervals; negative means relative.
        // Pack into a FILETIME for SetThreadpoolTimer.
        let due_time_100ns: i64 = {
            let intervals = duration.as_nanos() / 100;
            -(i64::try_from(intervals).unwrap_or(i64::MAX))
        };
        let due_time = FILETIME {
            dwLowDateTime: due_time_100ns.cast_unsigned().truncate(),
            dwHighDateTime: (due_time_100ns >> 32).cast_unsigned().truncate(),
        };

        // Arm the threadpool timer. The callback registered at creation
        // time will fire after `duration` elapses.
        unsafe {
            Win32_Threading::SetThreadpoolTimer(
                self.tp_timer,
                &raw const due_time,
                0, // no repeat
                0, // no window
            );
        }
    }
}

/// Context shared between the `TimerHandle` and the threadpool timer callback.
struct TimerCallbackContext {
    signal: litebox_common_linux::signal::Signal,
    target: SignalTarget,
}

#[derive(Clone)]
enum SignalTarget {
    Process(SignalProcessKey),
    Thread(ThreadHandle),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SignalProcessKey {
    scope: usize,
    process_id: litebox::process::ProcessId,
}

fn deliver_signal_to_target(target: &SignalTarget, signal: litebox_common_linux::signal::Signal) {
    match target {
        SignalTarget::Process(process_id) => {
            let thread = ACTIVE_THREADS
                .lock()
                .unwrap()
                .recipient_for_process(*process_id);
            if let Some(thread) = thread {
                thread.deliver_signal(signal);
            }
        }
        SignalTarget::Thread(thread) => thread.deliver_signal(signal),
    }
}

/// Threadpool timer callback registered via `CreateThreadpoolTimer`.
///
/// Delivers the signal to the process that created the timer.
unsafe extern "system" fn threadpool_timer_callback(
    _instance: Win32_Threading::PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    _timer: Win32_Threading::PTP_TIMER,
) {
    // Safety: `context` points to the `TimerCallbackContext` owned by the
    // `TimerHandle`. The handle's `Drop` impl waits for all in-flight
    // callbacks before dropping the context, so this reference is valid.
    let ctx = unsafe { &*context.cast::<TimerCallbackContext>() };
    deliver_signal_to_target(&ctx.target, ctx.signal);
}

/// Console control handler registered via `SetConsoleCtrlHandler`.
///
/// When the user presses Ctrl+C, this sets the SIGINT bit on one active thread
/// per managed process and interrupts them so the shim can deliver the
/// process-directed signal.
unsafe extern "system" fn ctrl_c_handler(ctrl_type: u32) -> i32 {
    if ctrl_type != windows_sys::Win32::System::Console::CTRL_C_EVENT {
        return 0; // FALSE — let the next handler deal with it
    }

    let threads = ACTIVE_THREADS.lock().unwrap().broadcast_recipients();
    for thread in threads {
        thread.deliver_signal(litebox_common_linux::signal::Signal::SIGINT);
    }

    1 // TRUE — we handled it
}

#[derive(Clone)]
pub struct ThreadHandle(Arc<Mutex<Option<ThreadHandleInner>>>);

struct ThreadHandleInner {
    handle: std::os::windows::io::OwnedHandle,
    tls: SendConstPtr<TlsState>,
    process_key: Option<SignalProcessKey>,
}

struct SendConstPtr<T>(*const T);
unsafe impl<T> Send for SendConstPtr<T> {}

thread_local! {
    static CURRENT_THREAD_HANDLE: RefCell<Option<ThreadHandle>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct ActiveThreadRegistry {
    by_process: BTreeMap<SignalProcessKey, alloc::vec::Vec<ThreadHandle>>,
    unscoped: alloc::vec::Vec<ThreadHandle>,
}

impl ActiveThreadRegistry {
    fn register(&mut self, process_key: Option<SignalProcessKey>, handle: ThreadHandle) {
        if let Some(process_key) = process_key {
            self.by_process.entry(process_key).or_default().push(handle);
        } else {
            self.unscoped.push(handle);
        }
    }

    fn unregister(&mut self, current: &ThreadHandle) {
        self.by_process.retain(|_, handles| {
            handles.retain(|handle| !Arc::ptr_eq(&handle.0, &current.0));
            !handles.is_empty()
        });
        self.unscoped
            .retain(|handle| !Arc::ptr_eq(&handle.0, &current.0));
    }

    fn recipient_for_process(&mut self, process_key: SignalProcessKey) -> Option<ThreadHandle> {
        let mut remove_process = false;
        let recipient = self.by_process.get_mut(&process_key).and_then(|handles| {
            handles.retain(ThreadHandle::is_registered);
            if handles.is_empty() {
                remove_process = true;
                None
            } else {
                handles.first().cloned()
            }
        });
        if remove_process {
            self.by_process.remove(&process_key);
        }
        recipient
    }

    fn broadcast_recipients(&mut self) -> alloc::vec::Vec<ThreadHandle> {
        let mut recipients = alloc::vec::Vec::new();
        self.by_process.retain(|_, handles| {
            handles.retain(ThreadHandle::is_registered);
            if let Some(handle) = handles.first().cloned() {
                recipients.push(handle);
                true
            } else {
                false
            }
        });
        self.unscoped.retain(ThreadHandle::is_registered);
        recipients.extend(self.unscoped.iter().cloned());
        recipients
    }
}

/// Global registry of all active managed thread handles, keyed by LiteBox
/// process where available.
///
/// Threads are registered in [`ThreadHandle::run_with_handle`] and
/// removed when the guard drops.
static ACTIVE_THREADS: Mutex<ActiveThreadRegistry> = Mutex::new(ActiveThreadRegistry {
    by_process: BTreeMap::new(),
    unscoped: alloc::vec::Vec::new(),
});

impl ThreadHandle {
    /// Creates a [`ThreadHandle`] referencing the calling OS thread.
    fn for_current_thread(tls: &TlsState, process_key: Option<SignalProcessKey>) -> ThreadHandle {
        let win_handle = unsafe {
            std::os::windows::io::BorrowedHandle::borrow_raw(
                windows_sys::Win32::System::Threading::GetCurrentThread(),
            )
        };
        ThreadHandle(Arc::new(Mutex::new(Some(ThreadHandleInner {
            handle: win_handle
                .try_clone_to_owned()
                .expect("failed to clone current thread handle"),
            tls: SendConstPtr(tls),
            process_key,
        }))))
    }

    /// Runs `f`, ensuring that [`CURRENT_THREAD_HANDLE`] is set while in the call to `f`.
    fn run_with_handle<R>(
        tls: &TlsState,
        process_key: Option<SignalProcessKey>,
        f: impl FnOnce() -> R,
    ) -> R {
        // Safety: `tls_state` lives for the duration of this call.
        unsafe { install_tls(tls) };

        let handle = Self::for_current_thread(tls, process_key);
        ACTIVE_THREADS
            .lock()
            .unwrap()
            .register(process_key, handle.clone());
        CURRENT_THREAD_HANDLE.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "thread is already registered with LiteBox",
            );
            *current = Some(handle.clone());
        });

        // Install TLS *after* all potentially-panicking setup so that an
        // early panic cannot leave the TLS slot pointing at dropped storage.
        // Safety: `tls_state` lives for the duration of this call.
        unsafe { install_tls(tls) };

        let _guard = litebox::utils::defer(move || {
            let current = CURRENT_THREAD_HANDLE.take().unwrap();
            ACTIVE_THREADS.lock().unwrap().unregister(&current);
            *current.0.lock().unwrap() = None;
            uninstall_tls();
        });
        f()
    }

    fn is_registered(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }

    fn process_key(&self) -> Option<SignalProcessKey> {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|inner| inner.process_key)
    }

    /// Sets a pending signal on this thread, wakes it from any condvar wait,
    /// and interrupts it so the shim processes the signal promptly.
    fn deliver_signal(&self, signal: litebox_common_linux::signal::Signal) {
        let bit: u32 = 1 << (signal.as_i32() - 1);

        // Set the pending signal bit and wake the condvar in one lock scope.
        {
            let inner = self.0.lock().unwrap();
            if let Some(inner) = inner.as_ref() {
                // Safety: the TLS pointer is valid as long as the thread is
                // alive, and we hold the thread handle lock.
                let tls = unsafe { &*inner.tls.0 };
                tls.pending_host_signals.fetch_or(bit, Ordering::SeqCst);

                let waker = tls.waiting_waker.load(Ordering::Acquire);
                if !waker.is_null() {
                    // SAFETY: `waker` was heap-allocated via `Box::into_raw` in
                    // `update_waker`. It remains valid here because
                    // `update_waker` acquires this same `ThreadHandleInner`
                    // mutex before freeing the old pointer, and we hold that
                    // mutex now.
                    let waker = unsafe { &*waker };
                    waker.wake();
                }
            }
        }

        self.interrupt(None);
    }

    /// Interrupt the thread represented by this handle, where `current` is the
    /// current thread's handle if it is managed by LiteBox.
    ///
    /// The basic strategy is this:
    /// 1. Suspend the target thread.
    /// 2. Access its TLS state to check if it's in the guest.
    /// 3. If it's not actually in the guest, set the interrupt flag and resume,
    ///    with some careful handling to make sure the interrupt flag is
    ///    evaluated upon return to the guest in all cases.
    /// 4. If it is in the guest, save the guest context and set the thread
    ///    context to resume at the interrupt callback.
    /// 5. Resume the target thread.
    fn interrupt(&self, current: Option<&ThreadHandle>) {
        /// Helper to lock two mutexes in address order, to prevent deadlock.
        fn lock_two<'a, T, U>(
            left: &'a Mutex<T>,
            right: &'a Mutex<U>,
        ) -> (std::sync::MutexGuard<'a, T>, std::sync::MutexGuard<'a, U>) {
            if std::ptr::from_ref(left).addr() < std::ptr::from_ref(right).addr() {
                let l = left.lock().unwrap();
                let r = right.lock().unwrap();
                (l, r)
            } else {
                let r = right.lock().unwrap();
                let l = left.lock().unwrap();
                (l, r)
            }
        }

        let (_current_guard, target) = if let Some(current) = current {
            if Arc::ptr_eq(&current.0, &self.0) {
                // Interrupting self; just set the flag.
                (unsafe { &*get_tls_ptr().unwrap() }).interrupt.set(true);
                return;
            }

            // Lock both the current and target thread handles so that this
            // thread is not suspended while holding the target thread lock.
            let (c, t) = lock_two(&current.0, &self.0);
            (Some(c), t)
        } else {
            // The current thread can't be suspended since it's not managed by LiteBox.
            (None, self.0.lock().unwrap())
        };
        let Some(inner) = target.as_ref() else {
            // The target is no longer managed by LiteBox.
            return;
        };

        // Suspend the target thread.
        let prev_count = unsafe {
            windows_sys::Win32::System::Threading::SuspendThread(inner.handle.as_raw_handle())
        };
        if prev_count == u32::MAX {
            return; // suspension failed — thread may have exited
        }
        let _resume_guard = litebox::utils::defer(|| unsafe {
            windows_sys::Win32::System::Threading::ResumeThread(inner.handle.as_raw_handle());
        });

        // SAFETY: The target thread is suspended by SuspendThread above, which
        // provides sequential consistency at the hardware level (the thread's
        // stores are fully visible). The fence prevents the compiler from
        // reordering our Cell reads/writes across the suspend/resume boundary.
        core::sync::atomic::fence(Ordering::SeqCst);

        // SAFETY: The target TLS state is accessible while the thread is
        // suspended.
        let target_tls = unsafe { &*inner.tls.0 };

        // Write the target interrupt flag.
        target_tls.interrupt.set(true);

        if !target_tls.is_in_guest.get() {
            // Not running in the guest. The interrupt flag will be checked
            // before returning to the guest, so just resume.
            return;
        }

        let guest_context = target_tls.guest_context_top.get().wrapping_sub(1);

        // Running in the guest. There are multiple possibilities:
        //
        // 1. The thread is in the middle of returning to the guest via the
        //    register pop path. Don't save context but do jump to the interrupt
        //    callback.
        // 2. The thread is in the middle of returning to the guest via the
        //    NtContinue path. Update the NtContinue context to point to the
        //    interrupt callback.
        // 3. The thread is beginning to handle an exception. Don't do anything;
        //    this path will check the interrupt flag.
        // 4. In the guest. Save the guest context and jump to the interrupt callback.

        // Get the current register context (including FP + XSTATE for save).
        // Use an extended context to capture AVX upper halves.
        let (mut context, xstate_ptr, _ctx_buf) =
            get_extended_thread_context(inner.handle.as_raw_handle());

        let rip = context.Rip.truncate();
        let stale_host_rip =
            target_tls.guest_teb_base.get() != 0 && !target_tls.guest_va_contains(rip);
        let run_interrupt_callback = if (switch_to_guest_start as *const () as usize
            ..switch_to_guest_end as *const () as usize)
            .contains(&rip)
        {
            // Case 1: in the switch-to-guest asm (FP restore, FS base write, or
            // register pop). The guest context is already saved in the
            // ExecutionContext, so just redirect to the interrupt callback.
            true
        } else if stale_host_rip || is_in_ntdll_or_this(rip) {
            // Case 2: execution is already back in host code even though the
            // bookkeeping still says "in guest". Leave the interrupt pending
            // and wait for the next real guest re-entry.
            if stale_host_rip {
                target_tls.is_in_guest.set(false);
            }
            false
        } else {
            // Check if the target is inside the syscall trampoline (transition
            // code that lives in guest VA).  The trampoline is about to enter
            // syscall_callback, which will check the interrupt flag.  Do NOT
            // save context and redirect — switch_to_guest would re-apply guest
            // FS base, breaking the trampoline's jump to host.
            let tramp_start = SYSCALL_TRAMPOLINE_START.load(Ordering::Acquire);
            let tramp_end = SYSCALL_TRAMPOLINE_END.load(Ordering::Acquire);
            if tramp_start != 0 && rip >= tramp_start && rip < tramp_end {
                // Trampoline will reach the shim momentarily; leave interrupt
                // pending just like Case 2.
                false
            } else {
                // Case 4: save the guest context and jump to interrupt callback.
                // The extended context includes XSTATE (AVX upper halves) when
                // supported, so save_guest_context + extract_avx_from_context
                // captures the full FP/SIMD state.
                save_guest_context(
                    unsafe { &mut *(guest_context as *mut litebox_common_linux::ExecutionContext) },
                    &context,
                    xstate_ptr,
                );
                true
            }
        };
        let target_tid = unsafe {
            windows_sys::Win32::System::Threading::GetThreadId(inner.handle.as_raw_handle())
        };
        target_tls.trace_transition_with_metadata(
            TransitionTraceKind::InterruptInject,
            u32::from(run_interrupt_callback),
            context.Rip,
            context.Rsp,
            context.R11,
            context.EFlags.into(),
            context.MxCsr,
            target_tid,
        );
        if run_interrupt_callback {
            set_context_to_interrupt_callback(target_tls, &mut context);
            let ok = unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext(
                    inner.handle.as_raw_handle(),
                    &raw const context,
                )
            };
            if ok == 0 {
                // SetThreadContext failed — thread resumes with original context.
                // The interrupt flag is already set, so the next syscall entry
                // will pick up the pending interrupt.
            }
        }

        // Ensure all Cell writes are committed before ResumeThread runs.
        core::sync::atomic::fence(Ordering::SeqCst);
    }
}

/// Updates `context` to jump to the interrupt callback with the given
/// `guest_context` pointer.
fn set_context_to_interrupt_callback(
    tls: &TlsState,
    context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    let required_flags = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
        | windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_INTEGER_AMD64;
    assert!(context.ContextFlags & required_flags == required_flags);
    context.Rip = interrupt_callback as *const () as usize as u64;
    context.Rsp = tls.host_sp.get().addr() as u64;
    context.Rbp = tls.host_bp.get().addr() as u64;
}

/// Saves the current guest register state and redirects control to the host
/// interrupt callback so `switch_to_guest` can restore guest FS base on re-entry.
fn save_context_and_redirect_to_interrupt_callback(
    tls: &TlsState,
    context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    let ctx_top = tls.guest_context_top.get();
    let exec_ctx =
        unsafe { &mut *(ctx_top.wrapping_sub(1) as *mut litebox_common_linux::ExecutionContext) };
    save_guest_context(exec_ctx, context, context as *const _);
    // Preserve TF in the saved guest state, but clear it from the host CONTEXT
    // before resuming into interrupt_callback so host code does not single-step.
    context.EFlags &= !0x100;
    set_context_to_interrupt_callback(tls, context);
}

/// Returns true if the given instruction pointer is in ntdll.dll or this module.
fn is_in_ntdll_or_this(ip: usize) -> bool {
    static BOUNDS: OnceLock<[std::ops::Range<usize>; 2]> = const { OnceLock::new() };

    let bounds = BOUNDS.get_or_init(|| {
        unsafe extern "C" {
            safe static __ImageBase: c_void;
        }
        fn module_bounds(module: *const c_void) -> std::ops::Range<usize> {
            let mut module_info = windows_sys::Win32::System::ProcessStatus::MODULEINFO::default();
            let r = unsafe {
                windows_sys::Win32::System::ProcessStatus::GetModuleInformation(
                    windows_sys::Win32::System::Threading::GetCurrentProcess(),
                    module.cast_mut(),
                    &raw mut module_info,
                    size_of_val(&module_info).try_into().unwrap(),
                )
            };
            assert_ne!(
                r,
                0,
                "GetModuleInformation failed: {}",
                std::io::Error::last_os_error()
            );
            let start = module_info.lpBaseOfDll.addr();
            let end = start + module_info.SizeOfImage as usize;
            start..end
        }

        let ntdll = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(windows_sys::w!(
                "ntdll.dll"
            ))
        };
        [module_bounds(ntdll), module_bounds(&raw const __ImageBase)]
    });

    bounds.iter().any(|b| b.contains(&ip))
}

impl litebox::platform::RawMutexProvider for WindowsUserland {
    type RawMutex = RawMutex;

    fn update_waker(&self, waker: Option<litebox::event::wait::Waker<Self>>)
    where
        Self: litebox::sync::RawSyncPrimitivesProvider,
    {
        if let Some(tls) = get_tls_ptr().map(|p| unsafe { &*p }) {
            let waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
            let old = tls.waiting_waker.swap(waker_ptr, Ordering::AcqRel);
            if !old.is_null() {
                // Synchronize with `deliver_signal`, which may be concurrently
                // reading the old waker pointer on another thread while holding
                // the `ThreadHandleInner` mutex. Acquiring the same mutex here
                // ensures that `deliver_signal` has finished using the pointer
                // before we free it.
                CURRENT_THREAD_HANDLE.with_borrow(|handle| {
                    let _guard = handle.as_ref().map(|handle| handle.0.lock().unwrap());
                    // SAFETY: old pointer was created by Box::into_raw in a previous
                    // call to update_waker. No other thread can be accessing it now
                    // because we synchronized via the ThreadHandleInner mutex above.
                    unsafe { drop(Box::from_raw(old)) };
                });
            }
        }
    }
}

// A skeleton of a raw mutex for Windows.
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

    #[expect(clippy::unnecessary_wraps)]
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // Compute timeout in ms
        let timeout_ms = match timeout {
            None => Win32_Threading::INFINITE, // no timeout
            Some(timeout) => {
                let ms = timeout.as_millis();
                ms.min(u128::from(Win32_Threading::INFINITE - 1)).truncate()
            }
        };

        let ok = unsafe {
            Win32_Threading::WaitOnAddress(
                (&raw const self.inner).cast::<c_void>(),
                (&raw const val).cast::<c_void>(),
                std::mem::size_of::<u32>(),
                timeout_ms,
            ) != 0
        };

        if ok {
            Ok(UnblockedOrTimedOut::Unblocked)
        } else {
            // Check why WaitOnAddress failed
            let err = unsafe { GetLastError() };
            match err {
                Win32_Foundation::ERROR_TIMEOUT => Ok(UnblockedOrTimedOut::TimedOut),
                _ => {
                    // Treat unexpected errors as spurious wakes — the caller
                    // will re-check the atomic value and retry.
                    Ok(UnblockedOrTimedOut::Unblocked)
                }
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_one(&self) -> bool {
        let mutex = core::ptr::from_ref(self.underlying_atomic()).cast::<c_void>();
        unsafe {
            Win32_Threading::WakeByAddressSingle(mutex);
        }
        // Windows doesn't report whether WakeByAddressSingle actually found a
        // waiter. RwLock's wake-up fallback logic remains correct if this is a
        // conservative false (like FreeBSD/DragonFly), but returning true
        // unconditionally can strand readers behind a stale writers-waiting bit.
        false
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0, "wake_many should be called with n > 0");
        let n: u32 = n.try_into().unwrap();

        let mutex = core::ptr::from_ref(self.underlying_atomic()).cast::<c_void>();
        unsafe {
            if n == 1 {
                Win32_Threading::WakeByAddressSingle(mutex);
            } else if n >= i32::MAX as u32 {
                Win32_Threading::WakeByAddressAll(mutex);
            } else {
                // Wake up `n` threads iteratively
                for _ in 0..n {
                    Win32_Threading::WakeByAddressSingle(mutex);
                }
            }
        }

        // For windows, the OS kernel does not tell us how many threads were actually woken up,
        // so we just return `n`
        n as usize
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

impl litebox::platform::IPInterfaceProvider for WindowsUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        // TUN path.
        if let Some(session) = &self.tun_session {
            return session
                .send(packet)
                .map_err(litebox::platform::SendError::Io);
        }

        // IPC path: write [u32 LE len][packet] as a single frame.
        if let Some(stream_lock) = self.ipc_stream.get() {
            use std::io::Write;
            let mut stream = stream_lock.lock().unwrap();
            let mut frame = alloc::vec::Vec::with_capacity(4 + packet.len());
            #[allow(clippy::cast_possible_truncation)]
            frame.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            frame.extend_from_slice(packet);

            let mut sent = 0usize;
            while sent < frame.len() {
                // Check if the transport was killed (by broker crash or runner shutdown).
                if self.ipc_dead.load(core::sync::atomic::Ordering::Relaxed) {
                    return Err(litebox::platform::SendError::Io(-1));
                }
                match stream.write(&frame[sent..]) {
                    Ok(0) => {
                        self.ipc_dead
                            .store(true, core::sync::atomic::Ordering::Relaxed);
                        return Err(litebox::platform::SendError::Io(-1));
                    }
                    Ok(n) => sent += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Wait for the socket to become writable (up to 10ms)
                        // instead of busy-spinning. Drop the lock while waiting
                        // so receive_ip_packet can make progress.
                        let raw = stream.raw_socket();
                        drop(stream);
                        #[repr(C)]
                        struct WsaPollFd {
                            fd: usize,
                            events: i16,
                            revents: i16,
                        }
                        #[link(name = "ws2_32")]
                        unsafe extern "system" {
                            fn WSAPoll(fds: *mut WsaPollFd, nfds: u32, timeout: i32) -> i32;
                        }
                        // WinSock WSAPoll bitmask values (different from POSIX!):
                        //   POLLOUT/POLLWRNORM = 0x0010
                        //   POLLERR = 0x0001, POLLHUP = 0x0002
                        const WS_POLLOUT: i16 = 0x0010;
                        const WS_POLLERR: i16 = 0x0001;
                        const WS_POLLHUP: i16 = 0x0002;
                        let mut pfd = WsaPollFd {
                            fd: raw,
                            events: WS_POLLOUT,
                            revents: 0,
                        };
                        unsafe {
                            WSAPoll(&mut pfd, 1, 10);
                        }
                        // Check for error/hangup on the socket.
                        if pfd.revents & (WS_POLLERR | WS_POLLHUP) != 0 {
                            self.ipc_dead
                                .store(true, core::sync::atomic::Ordering::Relaxed);
                            return Err(litebox::platform::SendError::Io(-1));
                        }
                        stream = stream_lock.lock().unwrap();
                    }
                    Err(_) => {
                        self.ipc_dead
                            .store(true, core::sync::atomic::Ordering::Relaxed);
                        return Err(litebox::platform::SendError::Io(-1));
                    }
                }
            }
            return Ok(());
        }

        panic!("send_ip_packet called without network transport configured");
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        // TUN path.
        if let Some(session) = &self.tun_session {
            return session
                .try_receive(packet)
                .map_err(|_| litebox::platform::ReceiveError::WouldBlock);
        }

        // IPC path: peek-validate-consume framing protocol.
        if let Some(stream_lock) = self.ipc_stream.get() {
            if self.ipc_dead.load(core::sync::atomic::Ordering::Relaxed) {
                return Err(litebox::platform::ReceiveError::WouldBlock);
            }

            let mut stream = stream_lock.lock().unwrap();

            // Step 1: Peek at the 4-byte length prefix.
            let mut len_buf = [0u8; 4];
            match stream.peek(&mut len_buf) {
                Ok(n) if n < 4 => {
                    if n == 0 {
                        // EOF — broker closed the connection.
                        self.ipc_dead
                            .store(true, core::sync::atomic::Ordering::Relaxed);
                    }
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
                Err(_) => {
                    self.ipc_dead
                        .store(true, core::sync::atomic::Ordering::Relaxed);
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
                Ok(_) => {}
            }

            let pkt_len = u32::from_le_bytes(len_buf) as usize;

            // Shutdown frame (len=0).
            if pkt_len == 0 {
                use std::io::Read;
                let mut discard = [0u8; 4];
                let _ = stream.read(&mut discard);
                self.ipc_dead
                    .store(true, core::sync::atomic::Ordering::Relaxed);
                return Err(litebox::platform::ReceiveError::Eof);
            }

            if pkt_len > packet.len() {
                self.ipc_dead
                    .store(true, core::sync::atomic::Ordering::Relaxed);
                return Err(litebox::platform::ReceiveError::ProtocolError);
            }

            // Step 2: Peek full frame to verify it's all available.
            let frame_len = 4 + pkt_len;
            let mut peek_buf = alloc::vec![0u8; frame_len];
            match stream.peek(&mut peek_buf) {
                Ok(n) if n < frame_len => {
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
                Err(_) => {
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
                Ok(_) => {}
            }

            // Step 3: Consume the 4-byte prefix.
            {
                use std::io::Read;
                let mut prefix = [0u8; 4];
                let _ = stream.read_exact(&mut prefix);
            }

            // Step 4: Read the packet body.
            {
                use std::io::Read;
                if stream.read_exact(&mut packet[..pkt_len]).is_err() {
                    self.ipc_dead
                        .store(true, core::sync::atomic::Ordering::Relaxed);
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
            }

            return Ok(pkt_len);
        }

        panic!("receive_ip_packet called without network transport configured");
    }
}

impl litebox::platform::TimeProvider for WindowsUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut ts = 0;
        unsafe { QueryUnbiasedInterruptTimePrecise(&raw mut ts) };
        Instant(ts)
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut filetime = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        unsafe {
            GetSystemTimePreciseAsFileTime(&raw mut filetime);
        }
        let FILETIME {
            dwLowDateTime: low,
            dwHighDateTime: high,
        } = filetime;
        let filetime = (u64::from(high) << 32) | u64::from(low);
        SystemTime { filetime }
    }
}

/// 100ns units returned by `QueryUnbiasedInterruptTimePrecise`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        let diff = self.0.checked_sub(earlier.0)?;
        // Convert from 100ns intervals to nanoseconds. This won't overflow in
        // our lifetimes.
        Some(Duration::from_nanos(diff * 100))
    }

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let duration_100ns: u64 = (duration.as_nanos() / 100).try_into().ok()?;
        let new = self.0.checked_add(duration_100ns)?;
        Some(Instant(new))
    }
}

pub struct SystemTime {
    // 100ns intervals since Windows epoch
    filetime: u64,
}

impl litebox::platform::SystemTime for SystemTime {
    // Windows epoch: Jan 1, 1601
    // Unix epoch: Jan 1, 1970
    // Difference: 11644473600 seconds
    // Intervals: 100ns intervals
    // Seconds per interval: 10^-7
    const UNIX_EPOCH: Self = SystemTime {
        filetime: 11_644_473_600 * 10_000_000,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        if self.filetime >= earlier.filetime {
            let diff_100ns = self.filetime - earlier.filetime;
            let nanos = diff_100ns * 100;
            let secs = nanos / 1_000_000_000;
            let remaining_nanos = nanos % 1_000_000_000;
            Ok(core::time::Duration::new(secs, remaining_nanos as u32))
        } else {
            let diff_100ns = earlier.filetime - self.filetime;
            let nanos = diff_100ns * 100;
            let secs = nanos / 1_000_000_000;
            let remaining_nanos = nanos % 1_000_000_000;
            Err(core::time::Duration::new(secs, remaining_nanos as u32))
        }
    }
}

pub struct PunchthroughToken<'a> {
    punchthrough: PunchthroughSyscall<'a, WindowsUserland>,
}

impl<'a> litebox::platform::PunchthroughToken for PunchthroughToken<'a> {
    type Punchthrough = PunchthroughSyscall<'a, WindowsUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            PunchthroughSyscall::SetFsBase { addr } => {
                // Use WindowsUserland's per-thread FS base management system
                WindowsUserland::set_thread_fs_base(addr);
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase => {
                // Use the stored FS base value from our per-thread storage
                Ok(WindowsUserland::get_thread_fs_base())
            }
        }
    }
}

impl litebox::platform::PunchthroughProvider for WindowsUserland {
    type PunchthroughToken<'a> = PunchthroughToken<'a>;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for WindowsUserland {
    fn debug_log_print(&self, msg: &str) {
        #[cfg(feature = "trace_debug")]
        {
            use std::io::Write;
            let _ = std::io::stderr().write_all(msg.as_bytes());
            append_trace_debug_log(msg);
        }
        let _ = msg;
    }
}

type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

impl litebox::platform::RawPointerProvider for WindowsUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

#[allow(
    clippy::match_same_arms,
    reason = "Iterate over all cases for prot_flags."
)]
fn prot_flags(flags: MemoryRegionPermissions) -> Win32_Memory::PAGE_PROTECTION_FLAGS {
    match (
        flags.contains(MemoryRegionPermissions::READ),
        flags.contains(MemoryRegionPermissions::WRITE),
        flags.contains(MemoryRegionPermissions::EXEC),
    ) {
        // no permissions
        (false, false, false) => Win32_Memory::PAGE_NOACCESS,
        // read-only
        (true, false, false) => Win32_Memory::PAGE_READONLY,
        // write-only (Windows doesn't have write-only, so we use r+w)
        (false, true, false) => Win32_Memory::PAGE_READWRITE,
        // read-write
        (true, true, false) => Win32_Memory::PAGE_READWRITE,
        // exeute-only (Windows doesn't have execute-only, so we use r+x)
        (false, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // read-execute
        (true, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // write-execute (Windows doesn't have write-execute, so we use rwx)
        (false, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
        // read-write-execute
        (true, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
    }
}

fn do_prefetch_on_range(start: usize, size: usize) {
    unsafe {
        let prefetch_entry = Win32_Memory::WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: start as *mut c_void,
            NumberOfBytes: size,
        };
        // Performance hint only — ignore failure.
        let _ = PrefetchVirtualMemory(GetCurrentProcess(), 1, &raw const prefetch_entry, 0);
    };
}

fn do_query_on_region(mbi: &mut Win32_Memory::MEMORY_BASIC_INFORMATION, base_addr: *mut c_void) {
    let ok = unsafe {
        Win32_Memory::VirtualQuery(
            base_addr,
            mbi,
            core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
        ) != 0
    };
    assert!(ok, "VirtualQuery addr={:p} failed: {}", base_addr, unsafe {
        GetLastError()
    });
}

/// Helper method to process a memory range by iterating through Windows memory regions.
///
/// Windows memory is managed in Virtual Address Descriptors (VADs) at the NT kernel level,
/// which means a single user-space range might span multiple regions. This helper method
/// queries each region within the specified range and applies the given operation.
///
/// # Parameters
/// - `range`: The memory range to process
/// - `operation`: A closure that takes (region_range, region_state) and returns Result<bool, E>.
///
/// # Panics
///
/// Panics if the operation returns false for any region.
fn partition_range_for_suggested_range(
    suggested_range: core::ops::Range<usize>,
) -> core::ops::Range<usize> {
    let anchor = if suggested_range.start != 0 {
        suggested_range.start
    } else {
        suggested_range
            .end
            .saturating_sub(1)
            .max(va_partitions::VA_MIN)
    };
    let partition_base = (anchor / va_partitions::PARTITION_SIZE) * va_partitions::PARTITION_SIZE;
    let start = partition_base.max(va_partitions::VA_MIN);
    let end = partition_base
        .saturating_add(va_partitions::PARTITION_SIZE)
        .min(TASK_ADDR_MAX.saturating_add(1));
    start..end
}

fn process_memory_range_by_regions<F, E>(
    mut range: core::ops::Range<usize>,
    mut operation: F,
) -> Result<(), E>
where
    F: FnMut(core::ops::Range<usize>, Win32_Memory::VIRTUAL_ALLOCATION_TYPE) -> Result<bool, E>,
{
    while !range.is_empty() {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut mbi, range.start as *mut c_void);
        debug_assert_eq!(range.start, mbi.BaseAddress as usize);
        let len = mbi.RegionSize.min(range.len());
        let success = operation(range.start..range.start + len, mbi.State)?;
        assert!(
            success,
            "operation failed on region {:p}-{:p}: {}",
            range.start as *mut c_void,
            (range.start + len) as *mut c_void,
            std::io::Error::last_os_error()
        );
        range = (range.start + len)..range.end;
    }
    Ok(())
}

macro_rules! debug_assert_alignment {
    ($r:ident, $page_size:expr) => {
        debug_assert!($r.start.is_multiple_of($page_size));
        debug_assert!($r.end.is_multiple_of($page_size));
    };
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    const TASK_ADDR_MIN: usize = va_partitions::VA_MIN;
    const TASK_ADDR_MAX: usize = TASK_ADDR_MAX;
    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        _noreserve: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert_alignment!(suggested_range, ALIGN);

        // A helper closure to reserve and commit memory in one go.
        //
        // Note that MEM_RESERVE requires the base address to be aligned to system allocation granularity,
        // while MEM_COMMIT only requires page-aligned address.
        //
        // To ensure future MEM_COMMIT calls on sub-ranges succeed, we always reserve the entire aligned range
        // (i.e., MEM_RESERVE size is also made aligned to system allocation granularity).
        let reserve_and_commit = |r: core::ops::Range<usize>,
                                  flags: Win32_Memory::PAGE_PROTECTION_FLAGS|
         -> *mut c_void {
            let aligned_start_addr = self.round_down_to_granu(r.start);
            let aligned_end_addr = self.round_up_to_granu(r.end);
            let ptr = unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    aligned_start_addr as *mut c_void,
                    aligned_end_addr - aligned_start_addr,
                    Win32_Memory::MEM_RESERVE,
                    Win32_Memory::PAGE_NOACCESS,
                    core::ptr::null_mut(),
                    0,
                )
            };
            if ptr.is_null() {
                core::ptr::null_mut()
            } else {
                let committed = unsafe {
                    VirtualAlloc2(
                        GetCurrentProcess(),
                        if r.start == 0 {
                            ptr
                        } else {
                            r.start as *mut c_void
                        },
                        r.len(),
                        Win32_Memory::MEM_COMMIT,
                        flags,
                        core::ptr::null_mut(),
                        0,
                    )
                };
                if committed.is_null() {
                    // Release the reserved VA to avoid a leak.
                    unsafe {
                        VirtualFree(ptr, 0, Win32_Memory::MEM_RELEASE);
                    }
                }
                committed
            }
        };
        let mut base_addr = suggested_range.start as *mut c_void;
        let size = suggested_range.len();
        // Windows has no direct MAP_GROWSDOWN equivalent. Guest stack growth is
        // serviced via explicit PageManager fault recovery instead, so the
        // initial mapping here is just a normal reservation/commit.
        let _ = can_grow_down;

        if suggested_range.start != 0 {
            assert!(suggested_range.start >= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MIN);
            assert!(suggested_range.end <= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MAX);

            let hinted_range_is_clean = is_va_range_clean(suggested_range.clone());
            let has_committed_page =
                process_memory_range_by_regions(suggested_range.clone(), |_r, state| {
                    if state == Win32_Memory::MEM_COMMIT {
                        Err(())
                    } else {
                        Ok(true)
                    }
                })
                .is_err();
            let suggested_range_is_slot0 = suggested_range.start < va_partitions::PARTITION_SIZE;
            if suggested_range_is_slot0
                && !hinted_range_is_clean
                && fixed_address_behavior == FixedAddressBehavior::Hint
            {
                // Slot 0 shares a VA partition with the host process, so a
                // guest-managed "free" gap can still overlap post-boot host
                // mappings that are invisible to the PageManager's VMA tree.
                // For non-fixed guest mmaps, fall back to a fresh OS-chosen
                // address inside the same partition instead of trying to map
                // on top of those host pages.
                base_addr = core::ptr::null_mut();
            } else if has_committed_page && fixed_address_behavior == FixedAddressBehavior::Hint {
                base_addr = core::ptr::null_mut();
            } else if has_committed_page
                && fixed_address_behavior == FixedAddressBehavior::NoReplace
            {
                trace_debugln!(
                    "[TRACE-ALLOC] fixed noreplace rejected start=0x{:x} end=0x{:x}: committed mapping present",
                    suggested_range.start,
                    suggested_range.end
                );
                let mut cursor = suggested_range.start;
                while cursor < suggested_range.end {
                    let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                    let ok = unsafe {
                        Win32_Memory::VirtualQuery(
                            cursor as *const c_void,
                            &raw mut mbi,
                            core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                        ) != 0
                    };
                    if !ok {
                        break;
                    }
                    let region_start = mbi.BaseAddress as usize;
                    let Some(region_end) = region_start.checked_add(mbi.RegionSize) else {
                        break;
                    };
                    let overlap_start = region_start.max(suggested_range.start);
                    let overlap_end = region_end.min(suggested_range.end);
                    if overlap_start < overlap_end {
                        trace_debugln!(
                            "[TRACE-ALLOC]   region start=0x{:x} end=0x{:x} state=0x{:x} protect=0x{:x}",
                            overlap_start,
                            overlap_end,
                            mbi.State,
                            mbi.Protect
                        );
                    }
                    cursor = region_end;
                }
                return Err(AllocationError::AddressInUse);
            } else {
                process_memory_range_by_regions(
                    suggested_range,
                    |r, state| -> Result<bool, std::convert::Infallible> {
                        let ok = match state {
                            // In case the region is already reserved, we just need to commit it.
                            // In case the region is already committed, decommit and recommit it.
                            Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_COMMIT => {
                                if state == Win32_Memory::MEM_COMMIT {
                                    // TODO: handle this race condition properly.
                                    assert_eq!(
                                        fixed_address_behavior,
                                        FixedAddressBehavior::Replace,
                                        "raced with another memory allocator"
                                    );
                                    let decommit_ok = unsafe {
                                        VirtualFree(
                                            r.start as *mut c_void,
                                            r.len(),
                                            Win32_Memory::MEM_DECOMMIT,
                                        )
                                    } != 0;
                                    assert!(
                                        decommit_ok,
                                        "VirtualFree(DECOMMIT) failed: {}",
                                        unsafe { GetLastError() }
                                    );
                                }
                                let ptr = unsafe {
                                    VirtualAlloc2(
                                        GetCurrentProcess(),
                                        r.start as *mut c_void,
                                        r.len(),
                                        Win32_Memory::MEM_COMMIT,
                                        prot_flags(initial_permissions),
                                        core::ptr::null_mut(),
                                        0,
                                    )
                                };
                                if ptr.is_null() {
                                    trace_debugln!(
                                        "[TRACE-ALLOC] commit failed start=0x{:x} len=0x{:x} state=0x{:x} err={}",
                                        r.start,
                                        r.len(),
                                        state,
                                        unsafe { GetLastError() }
                                    );
                                }
                                !ptr.is_null()
                            }
                            // In case the region is free, we need to reserve and commit it.
                            Win32_Memory::MEM_FREE => {
                                let ptr =
                                    reserve_and_commit(r.clone(), prot_flags(initial_permissions));
                                if ptr.is_null() {
                                    trace_debugln!(
                                        "[TRACE-ALLOC] reserve+commit failed start=0x{:x} len=0x{:x} err={}",
                                        r.start,
                                        r.len(),
                                        unsafe { GetLastError() }
                                    );
                                }
                                !ptr.is_null()
                            }
                            _ => unimplemented!(
                                "Unexpected memory state: {:?} when allocating pages",
                                state
                            ),
                        };
                        // Prefetch the memory range if requested
                        if ok && populate_pages_immediately {
                            do_prefetch_on_range(r.start, r.len());
                        }
                        Ok(ok)
                    },
                )
                .unwrap();
                return Ok(UserMutPtr::from_ptr(base_addr.cast()));
            }
        }

        debug_assert!(base_addr.is_null());

        // VirtualAlloc2 with address requirements to keep allocations within
        // the same partition as the original suggested range.  Without this,
        // NULL-base allocations can land outside the page manager's addr_max.
        let partition_range = partition_range_for_suggested_range(suggested_range.clone());
        #[repr(C)]
        struct MemAddressRequirements {
            lowest: *mut c_void,
            highest: *mut c_void,
            alignment: usize,
        }
        let mut addr_req = MemAddressRequirements {
            lowest: partition_range.start as *mut c_void,
            highest: (partition_range.end.saturating_sub(1)) as *mut c_void,
            alignment: 0,
        };
        #[repr(C)]
        struct MemExtendedParameter {
            type_and_reserved: u64,
            value: *mut c_void,
        }
        // Type = MemExtendedParameterAddressRequirements (1), shifted left by 32 bits per the API.
        let mut ext_param = MemExtendedParameter {
            type_and_reserved: 1_u64 << 32,
            value: &mut addr_req as *mut MemAddressRequirements as *mut c_void,
        };
        let aligned_size = self.round_up_to_granu(size);
        let mut ptr = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                core::ptr::null_mut(),
                aligned_size,
                Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_COMMIT,
                prot_flags(initial_permissions),
                &mut ext_param as *mut MemExtendedParameter as *mut _,
                1,
            )
        };
        if ptr.is_null() {
            // VirtualAlloc2 address requirements can still fail inside slot 0
            // when the host dirties parts of the partition after startup.
            // Probe the partition at allocation time and pick a truly free
            // sub-range rather than falling back outside the guest partition.
            let mut cursor = partition_range.start;
            while cursor < partition_range.end {
                let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                do_query_on_region(&mut mbi, cursor as *mut c_void);
                let region_start = mbi.BaseAddress as usize;
                let Some(next_cursor) = region_start.checked_add(mbi.RegionSize) else {
                    break;
                };
                let region_end = next_cursor.min(partition_range.end);
                if mbi.State == Win32_Memory::MEM_FREE {
                    let candidate = self.round_up_to_granu(region_start.max(partition_range.start));
                    if candidate
                        .checked_add(aligned_size)
                        .is_some_and(|end| end <= region_end)
                    {
                        let candidate_ptr = reserve_and_commit(
                            candidate..candidate + size,
                            prot_flags(initial_permissions),
                        );
                        if !candidate_ptr.is_null() {
                            ptr = candidate_ptr;
                            break;
                        }
                    }
                }
                cursor = next_cursor;
            }
            if ptr.is_null() {
                return Err(AllocationError::OutOfMemory);
            }
        }
        if populate_pages_immediately {
            do_prefetch_on_range(ptr as usize, size);
        }
        Ok(UserMutPtr::from_ptr(ptr.cast::<u8>()))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        debug_assert_alignment!(range, ALIGN);

        // Slot 0 shares its VA partition with the host process: the Rust
        // runtime heap, thread stacks, TEB/PEB, and other host allocations
        // all live in the same 1 TiB range. VirtualFree(MEM_DECOMMIT) on
        // guest pages in slot 0 can inadvertently decommit host-needed pages.
        //
        // We also must not try to scrub these pages manually: reset_pages()
        // can replace a mapping whose current host protection is already
        // PAGE_NOACCESS, so touching the bytes here would fault in the host.
        // Skip the explicit decommit for slot 0; the OS reclaims everything
        // when the process exits.
        //
        // Child partitions (slots 1+) are probed-clean and only contain
        // guest-allocated pages, so VirtualFree is safe for them.
        if range.start < va_partitions::PARTITION_SIZE {
            let slot0_owned = self
                .slot0_guest_reservations
                .lock()
                .unwrap()
                .iter()
                .any(|reserved| range.start >= reserved.start && range.end <= reserved.end);
            if !slot0_owned {
                return Ok(());
            }
        }

        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                if state == Win32_Memory::MEM_FREE {
                    return Ok(true);
                }
                let ret = unsafe {
                    VirtualFree(r.start as *mut c_void, r.len(), Win32_Memory::MEM_DECOMMIT)
                };
                if ret == 0 {
                    eprintln!(
                        "VirtualFree(MEM_DECOMMIT) failed on child partition region {:p}-{:p}: {}",
                        r.start as *mut c_void,
                        r.end as *mut c_void,
                        std::io::Error::last_os_error()
                    );
                }
                Ok(true)
            },
        )
        .expect("deallocate_pages failed");
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        debug_assert_alignment!(range, ALIGN);
        let flags = prot_flags(new_permissions);
        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                debug_assert_eq!(
                    state,
                    Win32_Memory::MEM_COMMIT,
                    "Trying to change permissions on a non-committed region: {:p}-{:p}",
                    r.start as *mut c_void,
                    r.end as *mut c_void
                );
                let mut old_protect: u32 = 0;
                Ok(unsafe {
                    VirtualProtect(r.start as *mut c_void, r.len(), flags, &raw mut old_protect)
                } != 0)
            },
        )
        .expect("update_permissions failed");
        Ok(())
    }

    /// Returns host memory regions that are reserved or committed at boot time.
    ///
    /// These are scanned once during `WindowsUserland::new()` via `VirtualQuery`
    /// and remain static for the platform's lifetime. The `PageManager` for each
    /// child process clamps these to its partition VA range automatically
    /// (see `Vmem::new()` in `litebox/src/mm/linux.rs`).
    ///
    /// **Known limitation:** Post-boot host allocations (lazy `LoadLibrary`,
    /// thread stacks, heap growth) are not reflected here. The partition-time
    /// `VirtualQuery` probing in `allocate_probed(is_va_range_clean)` provides
    /// a runtime safety net at partition creation time, but not at every
    /// individual page allocation.
    fn reserved_pages(&self) -> impl Iterator<Item = &std::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

/// Check whether a console input buffer contains actual keyboard character
/// data (KEY_EVENT with bKeyDown and a non-zero character). Returns `false`
/// for pipe/file handles (they don't support `PeekConsoleInputW`).
///
/// This avoids entering `stdin().read()` when the console input buffer only
/// contains mouse, focus, or window-resize events — those events signal
/// `WaitForSingleObject` but are not consumable by `ReadFile`/`ReadConsole`,
/// which would block.
fn console_has_key_data(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    let mut events_available: u32 = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Console::GetNumberOfConsoleInputEvents(
            handle,
            &mut events_available,
        )
    };
    if ok == 0 || events_available == 0 {
        return false;
    }

    // Peek up to 32 events without removing them.
    let mut buf: alloc::vec::Vec<windows_sys::Win32::System::Console::INPUT_RECORD> =
        core::iter::repeat_with(|| unsafe { core::mem::zeroed() })
            .take(events_available as usize)
            .collect();
    let mut events_read: u32 = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Console::PeekConsoleInputW(
            handle,
            buf.as_mut_ptr(),
            events_available,
            &mut events_read,
        )
    };
    if ok == 0 {
        return false;
    }

    for record in &buf[..events_read as usize] {
        if u32::from(record.EventType) == windows_sys::Win32::System::Console::KEY_EVENT {
            // SAFETY: EventType == KEY_EVENT guarantees the KeyEvent union variant.
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown != 0 {
                let ch = unsafe { key.uChar.UnicodeChar };
                if ch != 0 {
                    return true;
                }
            }
        }
    }
    false
}

/// Check whether a nonblocking console read can complete immediately.
///
/// In raw mode, any key-down character event is sufficient. In line-input
/// mode, `ReadFile` does not complete until a full line is available, so we
/// require an end-of-line/EOF character in the queued key events.
fn console_nonblocking_read_ready(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    let mut mode: u32 = 0;
    let ok = unsafe { windows_sys::Win32::System::Console::GetConsoleMode(handle, &mut mode) };
    if ok == 0 {
        return false;
    }
    let line_input_enabled = mode & windows_sys::Win32::System::Console::ENABLE_LINE_INPUT != 0;

    let mut events_available: u32 = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Console::GetNumberOfConsoleInputEvents(
            handle,
            &mut events_available,
        )
    };
    if ok == 0 || events_available == 0 {
        return false;
    }

    let mut buf: alloc::vec::Vec<windows_sys::Win32::System::Console::INPUT_RECORD> =
        core::iter::repeat_with(|| unsafe { core::mem::zeroed() })
            .take(events_available as usize)
            .collect();
    let mut events_read: u32 = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Console::PeekConsoleInputW(
            handle,
            buf.as_mut_ptr(),
            events_available,
            &mut events_read,
        )
    };
    if ok == 0 {
        return false;
    }

    for record in &buf[..events_read as usize] {
        if u32::from(record.EventType) != windows_sys::Win32::System::Console::KEY_EVENT {
            continue;
        }
        let key = unsafe { record.Event.KeyEvent };
        if key.bKeyDown == 0 {
            continue;
        }
        let ch = unsafe { key.uChar.UnicodeChar };
        if ch == 0 {
            continue;
        }
        if !line_input_enabled {
            return true;
        }
        if matches!(ch, 0x000d | 0x000a | 0x001a) {
            return true;
        }
    }

    false
}

#[derive(Clone, Copy)]
enum NonConsoleStdinReadiness {
    Ready,
    WouldBlock,
}

fn nonconsole_stdin_read_ready(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> NonConsoleStdinReadiness {
    use windows_sys::Win32::Storage::FileSystem;

    match unsafe { FileSystem::GetFileType(handle) } {
        FileSystem::FILE_TYPE_DISK => NonConsoleStdinReadiness::Ready,
        FileSystem::FILE_TYPE_PIPE => {
            let mut available: u32 = 0;
            let ok = unsafe {
                windows_sys::Win32::System::Pipes::PeekNamedPipe(
                    handle,
                    core::ptr::null_mut(),
                    0,
                    core::ptr::null_mut(),
                    &mut available,
                    core::ptr::null_mut(),
                )
            };
            if ok != 0 {
                return if available == 0 {
                    NonConsoleStdinReadiness::WouldBlock
                } else {
                    NonConsoleStdinReadiness::Ready
                };
            }
            match unsafe { GetLastError() } {
                Win32_Foundation::ERROR_BROKEN_PIPE
                | Win32_Foundation::ERROR_PIPE_NOT_CONNECTED => NonConsoleStdinReadiness::Ready,
                _ => NonConsoleStdinReadiness::WouldBlock,
            }
        }
        _ => NonConsoleStdinReadiness::WouldBlock,
    }
}

/// Drain non-key (mouse, focus, resize) events from the console input buffer
/// so that `WaitForSingleObject` does not immediately re-signal. Stops when
/// a key event with character data is found (leaving it for `stdin().read()`).
fn drain_non_key_console_events(handle: windows_sys::Win32::Foundation::HANDLE) {
    loop {
        let mut record: windows_sys::Win32::System::Console::INPUT_RECORD =
            unsafe { core::mem::zeroed() };
        let mut events_read: u32 = 0;
        let ok = unsafe {
            windows_sys::Win32::System::Console::PeekConsoleInputW(
                handle,
                &mut record,
                1,
                &mut events_read,
            )
        };
        if ok == 0 || events_read == 0 {
            return;
        }

        // If this is a key-down event with a real character, leave it for
        // stdin().read() to consume.
        if u32::from(record.EventType) == windows_sys::Win32::System::Console::KEY_EVENT {
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown != 0 {
                let ch = unsafe { key.uChar.UnicodeChar };
                if ch != 0 {
                    return;
                }
            }
        }

        // Consume this non-character event.
        unsafe {
            windows_sys::Win32::System::Console::ReadConsoleInputW(
                handle,
                &mut record,
                1,
                &mut events_read,
            );
        }
    }
}

/// Check if a handle is a console (as opposed to a pipe or file).
fn is_console_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    let mut mode: u32 = 0;
    unsafe { windows_sys::Win32::System::Console::GetConsoleMode(handle, &mut mode) != 0 }
}

/// Try `GetConsoleScreenBufferInfo` on the given handle IDs in order, returning
/// the first successful result as a `WindowSize`.
fn query_console_window_size(handle_ids: &[u32]) -> Option<litebox::platform::WindowSize> {
    for &id in handle_ids {
        let handle = unsafe { windows_sys::Win32::System::Console::GetStdHandle(id) };
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            continue;
        }
        let mut csbi = windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO::default();
        let ok = unsafe {
            windows_sys::Win32::System::Console::GetConsoleScreenBufferInfo(handle, &mut csbi)
        };
        if ok != 0 {
            return Some(litebox::platform::WindowSize {
                rows: (csbi.srWindow.Bottom - csbi.srWindow.Top + 1) as u16,
                cols: (csbi.srWindow.Right - csbi.srWindow.Left + 1) as u16,
                xpixel: 0,
                ypixel: 0,
            });
        }
    }
    // Last resort: open CONOUT$ to bypass stdout/stderr redirection.
    // This gives us a handle to the active console screen buffer even when
    // all three standard handles are redirected away from the console.
    if let Some(conout) = open_conout() {
        let mut csbi = windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO::default();
        let ok = unsafe {
            windows_sys::Win32::System::Console::GetConsoleScreenBufferInfo(conout, &mut csbi)
        };
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(conout);
        }
        if ok != 0 {
            return Some(litebox::platform::WindowSize {
                rows: (csbi.srWindow.Bottom - csbi.srWindow.Top + 1) as u16,
                cols: (csbi.srWindow.Right - csbi.srWindow.Left + 1) as u16,
                xpixel: 0,
                ypixel: 0,
            });
        }
    }

    None
}

/// RAII guard that closes a Win32 HANDLE on drop. Used when we open console
/// device handles (CONIN$/CONOUT$) via `CreateFileW` that must be closed.
struct OwnedConsoleHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for OwnedConsoleHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Open `CONIN$` to get a handle to the console input buffer, bypassing any
/// stdin redirection. Returns `None` if the process has no attached console.
fn open_conin() -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Storage::FileSystem;
    // "CONIN$\0" as UTF-16.
    let name: [u16; 7] = [
        b'C' as u16,
        b'O' as u16,
        b'N' as u16,
        b'I' as u16,
        b'N' as u16,
        b'$' as u16,
        0,
    ];
    let handle = unsafe {
        FileSystem::CreateFileW(
            name.as_ptr(),
            Win32_Foundation::GENERIC_READ | Win32_Foundation::GENERIC_WRITE,
            FileSystem::FILE_SHARE_READ,
            core::ptr::null(),
            FileSystem::OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        None
    } else {
        Some(handle)
    }
}

/// Open `CONOUT$` to get a handle to the active console screen buffer,
/// bypassing any stdout/stderr redirection. Returns `None` if the process
/// has no attached console.
fn open_conout() -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Storage::FileSystem;
    // "CONOUT$\0" as UTF-16.
    let name: [u16; 8] = [
        b'C' as u16,
        b'O' as u16,
        b'N' as u16,
        b'O' as u16,
        b'U' as u16,
        b'T' as u16,
        b'$' as u16,
        0,
    ];
    let handle = unsafe {
        FileSystem::CreateFileW(
            name.as_ptr(),
            Win32_Foundation::GENERIC_READ | Win32_Foundation::GENERIC_WRITE,
            FileSystem::FILE_SHARE_WRITE,
            core::ptr::null(),
            FileSystem::OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        None
    } else {
        Some(handle)
    }
}

impl litebox::platform::StdioProvider for WindowsUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let _stdin_read = self.stdin_read_serial.lock().unwrap();
        let stdin_handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        let is_console = stdin_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            && !stdin_handle.is_null()
            && is_console_handle(stdin_handle);

        loop {
            if self
                .stdin_cancelled
                .load(core::sync::atomic::Ordering::Acquire)
            {
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if stdin_handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
                || stdin_handle.is_null()
            {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            // Wait with 500ms timeout so we can re-check cancellation.
            let result = unsafe { Win32_Threading::WaitForSingleObject(stdin_handle, 500) };
            if result != Win32_Foundation::WAIT_OBJECT_0 {
                continue; // timeout — loop back
            }

            if is_console {
                // Console handles signal for ANY input event (mouse, focus,
                // resize). Only enter stdin().read() when there is actual
                // keyboard character data, otherwise drain the non-key events
                // and loop back to WaitForSingleObject.
                if !console_has_key_data(stdin_handle) {
                    drain_non_key_console_events(stdin_handle);
                    continue;
                }
            }

            // Either pipe/file (signal means data) or console with key data.
            use std::io::Read as _;
            return std::io::stdin().read(buf).map_err(|err| {
                if err.kind() == std::io::ErrorKind::BrokenPipe {
                    litebox::platform::StdioReadError::Closed
                } else {
                    eprintln!("stdin read error: {err}");
                    litebox::platform::StdioReadError::Closed
                }
            });
        }
    }

    fn read_from_stdin_nonblocking(
        &self,
        buf: &mut [u8],
    ) -> Result<usize, litebox::platform::StdioReadError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self
            .stdin_cancelled
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return Err(litebox::platform::StdioReadError::Closed);
        }
        let _stdin_read = match self.stdin_read_serial.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(litebox::platform::StdioReadError::WouldBlock);
            }
            Err(std::sync::TryLockError::Poisoned(err)) => err.into_inner(),
        };

        if self
            .stdin_cancelled
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return Err(litebox::platform::StdioReadError::Closed);
        }

        let stdin_handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        if stdin_handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(litebox::platform::StdioReadError::Closed);
        }

        if is_console_handle(stdin_handle) {
            if !console_nonblocking_read_ready(stdin_handle) {
                drain_non_key_console_events(stdin_handle);
                if !console_nonblocking_read_ready(stdin_handle) {
                    return Err(litebox::platform::StdioReadError::WouldBlock);
                }
            }
        } else {
            if matches!(
                nonconsole_stdin_read_ready(stdin_handle),
                NonConsoleStdinReadiness::WouldBlock
            ) {
                return Err(litebox::platform::StdioReadError::WouldBlock);
            }
        }

        use std::io::Read as _;
        std::io::stdin().read(buf).map_err(|err| {
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                litebox::platform::StdioReadError::Closed
            } else if err.kind() == std::io::ErrorKind::WouldBlock {
                litebox::platform::StdioReadError::WouldBlock
            } else {
                panic!("unhandled error {err}")
            }
        })
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        use std::io::Write as _;
        match stream {
            litebox::platform::StdioOutStream::Stdout => {
                let mut stdout = std::io::stdout();
                stdout.write_all(buf).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        eprintln!("stdout write error: {err}");
                        litebox::platform::StdioWriteError::Closed
                    }
                })?;
                stdout.flush().map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        eprintln!("stdout flush error: {err}");
                        litebox::platform::StdioWriteError::Closed
                    }
                })?;
                Ok(buf.len())
            }
            litebox::platform::StdioOutStream::Stderr => {
                let mut stderr = std::io::stderr();
                stderr.write_all(buf).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        eprintln!("stderr write error: {err}");
                        litebox::platform::StdioWriteError::Closed
                    }
                })?;
                stderr.flush().map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        eprintln!("stderr flush error: {err}");
                        litebox::platform::StdioWriteError::Closed
                    }
                })?;
                Ok(buf.len())
            }
        }
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        use litebox::platform::StdioStream;
        use std::io::IsTerminal as _;
        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }

    fn get_terminal_attributes(
        &self,
        stream: litebox::platform::StdioStream,
    ) -> Result<litebox::platform::TerminalAttributes, litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }
        let state = self.console_terminal.lock().unwrap();
        Ok(state.attrs.clone())
    }

    fn set_terminal_attributes(
        &self,
        stream: litebox::platform::StdioStream,
        attrs: &litebox::platform::TerminalAttributes,
        _when: litebox::platform::SetTermiosWhen,
    ) -> Result<(), litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }

        // Find a usable console input handle for GetConsoleMode/SetConsoleMode.
        // Try STD_INPUT_HANDLE first; if stdin is redirected, fall back to
        // opening CONIN$ which bypasses redirection to reach the actual
        // console input buffer.
        let stdin_handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        let conin_guard: Option<OwnedConsoleHandle>;
        let input_handle;

        if stdin_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            && is_console_handle(stdin_handle)
        {
            input_handle = stdin_handle;
            conin_guard = None;
        } else if let Some(h) = open_conin() {
            input_handle = h;
            conin_guard = Some(OwnedConsoleHandle(h));
        } else {
            // No console input handle available — do NOT update cached state.
            return Err(litebox::platform::StdioIoctlError::OsError(
                windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE as i32,
            ));
        }
        // Keep the guard alive until the end of this function.
        let _conin_guard = conin_guard;

        let mut mode: u32 = 0;
        let ok =
            unsafe { windows_sys::Win32::System::Console::GetConsoleMode(input_handle, &mut mode) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(litebox::platform::StdioIoctlError::OsError(err as i32));
        }

        const ECHO: u32 = 0x0008;
        const ICANON: u32 = 0x0002;
        const ISIG: u32 = 0x0001;
        const ENABLE_ECHO_INPUT: u32 = windows_sys::Win32::System::Console::ENABLE_ECHO_INPUT;
        const ENABLE_LINE_INPUT: u32 = windows_sys::Win32::System::Console::ENABLE_LINE_INPUT;
        const ENABLE_PROCESSED_INPUT: u32 =
            windows_sys::Win32::System::Console::ENABLE_PROCESSED_INPUT;

        if attrs.c_lflag & ECHO != 0 {
            mode |= ENABLE_ECHO_INPUT;
        } else {
            mode &= !ENABLE_ECHO_INPUT;
        }
        if attrs.c_lflag & ICANON != 0 {
            mode |= ENABLE_LINE_INPUT;
        } else {
            mode &= !ENABLE_LINE_INPUT;
        }
        if attrs.c_lflag & ISIG != 0 {
            mode |= ENABLE_PROCESSED_INPUT;
        } else {
            mode &= !ENABLE_PROCESSED_INPUT;
        }

        let ok = unsafe { windows_sys::Win32::System::Console::SetConsoleMode(input_handle, mode) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(litebox::platform::StdioIoctlError::OsError(err as i32));
        }

        // Store attributes in shared state only AFTER SetConsoleMode succeeds.
        // This ensures get_terminal_attributes never returns attributes that
        // were not actually applied to the host console.
        {
            let mut state = self.console_terminal.lock().unwrap();
            state.attrs = attrs.clone();
        }

        Ok(())
    }

    fn get_window_size(
        &self,
        stream: litebox::platform::StdioStream,
    ) -> Result<litebox::platform::WindowSize, litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }

        let state = self.console_terminal.lock().unwrap();
        if state.winsize_overridden {
            return Ok(state.winsize);
        }
        drop(state);

        // Map the stream to the corresponding Windows console handle ID.
        let primary_id = match stream {
            litebox::platform::StdioStream::Stdin => {
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE
            }
            litebox::platform::StdioStream::Stdout => {
                windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE
            }
            litebox::platform::StdioStream::Stderr => {
                windows_sys::Win32::System::Console::STD_ERROR_HANDLE
            }
        };

        // GetConsoleScreenBufferInfo only works on output handles.
        // Try the selected handle first, then fall back to stdout, then stderr.
        // This handles the mixed-redirection case (e.g. stdin is tty, stdout
        // is redirected — stderr may still be attached to the console).
        let fallback_ids = [
            primary_id,
            windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
            windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
        ];

        query_console_window_size(&fallback_ids)
            .ok_or(litebox::platform::StdioIoctlError::NotATerminal)
    }

    fn set_window_size(
        &self,
        stream: litebox::platform::StdioStream,
        size: &litebox::platform::WindowSize,
    ) -> Result<(), litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }
        // Store so TIOCSWINSZ round-trips with TIOCGWINSZ.
        let mut state = self.console_terminal.lock().unwrap();
        state.winsize = *size;
        state.winsize_overridden = true;
        Ok(())
    }

    fn poll_stdin_readable(&self) -> bool {
        let stdin_handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        if stdin_handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return false;
        }

        if is_console_handle(stdin_handle) {
            // For console handles, only report readability when a console read
            // can complete immediately in the current line/raw mode.
            console_nonblocking_read_ready(stdin_handle)
        } else {
            matches!(
                nonconsole_stdin_read_ready(stdin_handle),
                NonConsoleStdinReadiness::Ready
            )
        }
    }

    fn cancel_stdin(&self) {
        self.stdin_cancelled
            .store(true, core::sync::atomic::Ordering::Release);
    }
}

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 30, WindowsUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for WindowsUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );

        match unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                core::ptr::null_mut(),
                size,
                Win32_Memory::MEM_COMMIT | Win32_Memory::MEM_RESERVE,
                Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        } {
            addr if addr.is_null() => None,
            addr => Some((addr as usize, size)),
        }
    }

    unsafe fn free(_addr: usize) {
        unimplemented!("Memory deallocation is not implemented for Windows yet.");
    }
}

unsafe extern "C" {
    // Defined in asm blocks above
    #[allow(dead_code)]
    fn syscall_callback() -> isize;
    fn syscall_callback_redzone() -> isize;
    fn exception_callback() -> isize;
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.init(ctx));
}

unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.tls.trace_transition(
        TransitionTraceKind::Syscall,
        thread_ctx.ctx.orig_rax as u32,
        thread_ctx.ctx.rip as u64,
        thread_ctx.ctx.rsp as u64,
        thread_ctx.ctx.r11 as u64,
        thread_ctx.ctx.eflags as u64,
    );
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.syscall(ctx));
}

/// Check whether the page at `addr` is committed (has physical storage).
///
/// Uses `VirtualQuery` to inspect the page state. Returns `true` only for
/// `MEM_COMMIT` pages; `MEM_RESERVE` and `MEM_FREE` return `false`.
fn is_page_committed(addr: usize) -> bool {
    let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
    // Safety: VirtualQuery reads kernel VA metadata; the address may be
    // unmapped but VirtualQuery still succeeds (returns MEM_FREE).
    let ok = unsafe {
        Win32_Memory::VirtualQuery(
            addr as *const c_void,
            &raw mut mbi,
            core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
        ) != 0
    };
    ok && mbi.State == Win32_Memory::MEM_COMMIT
}

/// Check whether every page in `[addr, addr + len)` is committed and readable.
fn is_readable_committed_range(addr: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = addr.checked_add(len - 1) else {
        return false;
    };
    let mut current = addr;
    while current <= end {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        let ok = unsafe {
            Win32_Memory::VirtualQuery(
                current as *const c_void,
                &raw mut mbi,
                core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        };
        if !ok || mbi.State != Win32_Memory::MEM_COMMIT {
            return false;
        }
        let protect = mbi.Protect;
        if protect == 0
            || protect == Win32_Memory::PAGE_NOACCESS
            || (protect & Win32_Memory::PAGE_GUARD) != 0
        {
            return false;
        }
        let region_base = mbi.BaseAddress as usize;
        let Some(next) = region_base.checked_add(mbi.RegionSize) else {
            return false;
        };
        if next <= current {
            return false;
        }
        current = next;
    }
    true
}

/// Check whether every page in `[addr, addr + len)` is committed and writable.
fn is_writable_committed_range(addr: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = addr.checked_add(len - 1) else {
        return false;
    };
    let mut current = addr;
    while current <= end {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        let ok = unsafe {
            Win32_Memory::VirtualQuery(
                current as *const c_void,
                &raw mut mbi,
                core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        };
        if !ok || mbi.State != Win32_Memory::MEM_COMMIT {
            return false;
        }
        let protect = mbi.Protect;
        let writable = protect == Win32_Memory::PAGE_READWRITE
            || protect == Win32_Memory::PAGE_WRITECOPY
            || protect == Win32_Memory::PAGE_EXECUTE_READWRITE
            || protect == Win32_Memory::PAGE_EXECUTE_WRITECOPY;
        if !writable || (protect & Win32_Memory::PAGE_GUARD) != 0 {
            return false;
        }
        let region_base = mbi.BaseAddress as usize;
        let Some(next) = region_base.checked_add(mbi.RegionSize) else {
            return false;
        };
        if next <= current {
            return false;
        }
        current = next;
    }
    true
}

/// Synthesize a Linux-style x86 page-fault error code from Windows
/// exception information.
///
/// Bits:
/// - 0: present (page committed but access denied)
/// - 1: write fault
/// - 2: user-mode (always set)
/// - 4: instruction fetch (DEP)
///
/// `read_write_flag` is `ExceptionInformation[0]` from
/// `EXCEPTION_ACCESS_VIOLATION`: 0 = read, 1 = write, 8 = DEP.
fn synthesize_pf_error_code(is_present: bool, read_write_flag: usize) -> u32 {
    u32::from(is_present)
        | match read_write_flag {
            0 => 0,      // read fault
            8 => 1 << 4, // DEP (instruction fetch)
            _ => 1 << 1, // write fault
        }
        | 4 // bit 2: user-mode
}

unsafe extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext<'_>,
    exception_record: &EXCEPTION_RECORD,
) {
    thread_ctx.tls.trace_transition(
        TransitionTraceKind::ShimException,
        exception_record.ExceptionCode as u32,
        thread_ctx.ctx.rip as u64,
        thread_ctx.ctx.rsp as u64,
        thread_ctx.ctx.r11 as u64,
        thread_ctx.ctx.eflags as u64,
    );
    let (exception, error_code, cr2) = match exception_record.ExceptionCode {
        Win32_Foundation::EXCEPTION_ACCESS_VIOLATION => {
            let info = exception_record.ExceptionInformation;
            let read_write_flag = info[0];
            let faulting_address = info[1];
            if read_write_flag == 0 && faulting_address == !0 {
                // This is probably a #GP, not a #PF.
                (Exception::GENERAL_PROTECTION_FAULT, 0, 0)
            } else {
                let is_present = is_page_committed(faulting_address);
                let error_code = synthesize_pf_error_code(is_present, read_write_flag);
                (Exception::PAGE_FAULT, error_code, faulting_address)
            }
        }
        Win32_Foundation::EXCEPTION_ILLEGAL_INSTRUCTION => (Exception::INVALID_OPCODE, 0, 0),
        Win32_Foundation::EXCEPTION_PRIV_INSTRUCTION => {
            // Maps to #GP (General Protection Fault). On x86, HLT triggers
            // this in user mode; glibc uses HLT as an unreachable abort trap.
            (Exception::GENERAL_PROTECTION_FAULT, 0, 0)
        }
        Win32_Foundation::EXCEPTION_BREAKPOINT => (Exception::BREAKPOINT, 0, 0),
        Win32_Foundation::EXCEPTION_INT_DIVIDE_BY_ZERO => (Exception::DIVIDE_ERROR, 0, 0),
        // Floating-point exceptions: map to #MF (x87) or #XF (SIMD).
        // The original NTSTATUS is carried in `error_code` so the shim can
        // reconstruct the correct ExceptionCode for KiUserExceptionDispatcher.
        Win32_Foundation::EXCEPTION_FLT_DENORMAL_OPERAND
        | Win32_Foundation::EXCEPTION_FLT_DIVIDE_BY_ZERO
        | Win32_Foundation::EXCEPTION_FLT_INEXACT_RESULT
        | Win32_Foundation::EXCEPTION_FLT_INVALID_OPERATION
        | Win32_Foundation::EXCEPTION_FLT_OVERFLOW
        | Win32_Foundation::EXCEPTION_FLT_STACK_CHECK
        | Win32_Foundation::EXCEPTION_FLT_UNDERFLOW =>
        {
            #[allow(clippy::cast_sign_loss)]
            (
                Exception::MATH_FAULT,
                exception_record.ExceptionCode as u32,
                0,
            )
        }
        Win32_Foundation::EXCEPTION_INT_OVERFLOW => {
            // Carry the original NTSTATUS (0xC0000095) in error_code so the
            // shim can distinguish from STATUS_INTEGER_DIVIDE_BY_ZERO.
            (Exception::DIVIDE_ERROR, 0xC000_0095u32, 0)
        }
        Win32_Foundation::EXCEPTION_STACK_OVERFLOW => {
            // Stack overflow: treat as access violation on the guard page.
            (Exception::PAGE_FAULT, 0, 0)
        }
        code => panic!("Unhandled Win32 exception code: {:#x}", code),
    };

    let info = litebox::shim::ExceptionInfo {
        exception,
        error_code,
        cr2,
        kernel_mode: false,
    };

    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.exception(ctx, &info));
}

unsafe extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.tls.is_in_guest.set(false);
    thread_ctx.tls.trace_transition(
        TransitionTraceKind::InterruptHandler,
        u32::from(thread_ctx.tls.interrupt.get()),
        thread_ctx.ctx.rip as u64,
        thread_ctx.ctx.rsp as u64,
        thread_ctx.ctx.r11 as u64,
        thread_ctx.ctx.eflags as u64,
    );
    thread_ctx.call_shim(|shim, ctx, interrupt| {
        if interrupt {
            shim.interrupt(ctx)
        } else {
            // We likely got here just to restore fsbase, so don't bother the
            // shim.
            ContinueOperation::Resume
        }
    });
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &'a mut litebox_common_linux::ExecutionContext,
    tls: &'a TlsState,
}

impl ThreadContext<'_> {
    /// Calls `f` in order to call into a shim entrypoint.
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
            &mut litebox_common_linux::ExecutionContext,
            bool,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        let op = f(self.shim, self.ctx, self.tls.interrupt.replace(false));
        match op {
            ContinueOperation::Resume => unsafe { switch_to_guest(self.ctx) },
            ContinueOperation::Terminate => {
                if self.ctx.rax != 0 {
                    self.tls.dump_transition_trace("thread-terminate");
                }
            }
        }
    }
}

impl litebox::platform::SystemInfoProvider for WindowsUserland {
    fn get_syscall_entry_point(&self) -> usize {
        if self.prefer_redzone_syscall_entry.load(Ordering::Relaxed) {
            syscall_callback_redzone as *const () as usize
        } else {
            syscall_callback as *const () as usize
        }
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // Windows doesn't have VDSO equivalent, return None
        None
    }

    fn current_processor_number(&self) -> u32 {
        // Keep guest rseq state aligned with the virtual CPU-0 view exposed by
        // the Windows userland stack.
        0
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

/// WindowsUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for WindowsUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(new_tls: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(new_tls)
    }

    fn clear_guest_thread_local_storage() {
        Self::init_thread_fs_base();
    }
}

impl litebox::platform::CrngProvider for WindowsUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

/// Page-fault recovery for guest-managed mappings on Windows userland.
///
/// Guest user-mode faults are surfaced through the VEH path. The Linux shim can
/// route those faults into the PageManager so grow-down stack VMAs expand the
/// same way kernel-backed platforms do.
impl litebox::mm::linux::VmemPageFaultHandler for WindowsUserland {
    const HANDLE_USER_PAGE_FAULTS: bool = true;

    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        let fault_addr = fault_addr & !(litebox::mm::linux::PAGE_SIZE - 1);
        let permissions_bits: u8 = flags
            .intersection(litebox::mm::linux::VmFlags::VM_ACCESS_FLAGS)
            .bits()
            .try_into()
            .unwrap();
        let permissions = MemoryRegionPermissions::from_bits(permissions_bits).unwrap();
        if permissions.is_empty() {
            return Err(litebox::mm::linux::PageFaultError::AccessError(
                "no accessible mapping",
            ));
        }

        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        // SAFETY: We query our own process address space at the page-aligned
        // fault address and provide a valid output buffer of the correct size.
        let ok = unsafe {
            Win32_Memory::VirtualQuery(
                fault_addr as *const c_void,
                &raw mut mbi,
                core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        };
        if !ok {
            return Err(litebox::mm::linux::PageFaultError::AllocationFailed);
        }

        match mbi.State {
            Win32_Memory::MEM_COMMIT => Ok(()),
            Win32_Memory::MEM_RESERVE => {
                // SAFETY: This commits exactly one page inside an existing
                // reserved region in the current process. The PageManager only
                // reaches this path for guest-managed mappings that it owns.
                let ptr = unsafe {
                    VirtualAlloc2(
                        GetCurrentProcess(),
                        fault_addr as *mut c_void,
                        litebox::mm::linux::PAGE_SIZE,
                        Win32_Memory::MEM_COMMIT,
                        prot_flags(permissions),
                        core::ptr::null_mut(),
                        0,
                    )
                };
                if ptr.is_null() {
                    return Err(litebox::mm::linux::PageFaultError::AllocationFailed);
                }
                Ok(())
            }
            _ => Err(litebox::mm::linux::PageFaultError::AccessError(
                "no mapping",
            )),
        }
    }

    fn access_error(error_code: u64, flags: litebox::mm::linux::VmFlags) -> bool {
        let present = (error_code & 0x1) != 0;
        let write = (error_code & 0x2) != 0;
        let instruction_fetch = (error_code & 0x10) != 0;
        if write {
            return !flags.contains(litebox::mm::linux::VmFlags::VM_WRITE);
        }
        if instruction_fetch {
            // Like read-side protection faults on the kernel platforms, a
            // present instruction-fetch fault is an unrecoverable permission
            // violation (DEP / NX), not a missing-page condition that the
            // PageManager can repair. Only non-present executable faults should
            // flow into handle_page_fault().
            return present || !flags.contains(litebox::mm::linux::VmFlags::VM_EXEC);
        }
        if present {
            return true;
        }
        (flags & litebox::mm::linux::VmFlags::VM_ACCESS_FLAGS).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Range;
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;
    use std::thread::sleep;

    use super::CURRENT_THREAD_HANDLE;
    use crate::WindowsUserland;
    use crate::process_memory_range_by_regions;
    use litebox::mm::PageManager;
    use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
    use litebox::platform::PageManagementProvider;
    use litebox::platform::RawConstPointer;
    use litebox::platform::RawMutex;
    use litebox::platform::page_mgmt::FixedAddressBehavior;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox::process::ProcessId;

    static SIGNAL_ROUTING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn collect_regions(r: Range<usize>) -> Vec<(Range<usize>, u32)> {
        let mut regions = Vec::new();
        process_memory_range_by_regions(
            r,
            |region, state| -> Result<bool, core::convert::Infallible> {
                regions.push((region, state));
                Ok(true)
            },
        )
        .unwrap();
        regions
    }

    struct ManagedTestThread {
        handle: super::ThreadHandle,
        release_tx: std::sync::mpsc::Sender<()>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for ManagedTestThread {
        fn drop(&mut self) {
            let _ = self.release_tx.send(());
            if let Some(join) = self.join.take() {
                join.join().unwrap();
            }
        }
    }

    fn spawn_managed_test_thread(scope: usize, process_id: ProcessId) -> ManagedTestThread {
        let (handle_tx, handle_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            super::ensure_tls_index();
            let tls = super::TlsState::new();
            super::ThreadHandle::run_with_handle(
                &tls,
                Some(super::SignalProcessKey { scope, process_id }),
                || {
                    let handle = CURRENT_THREAD_HANDLE.with_borrow(|current| {
                        current
                            .clone()
                            .expect("test thread should be registered with LiteBox")
                    });
                    handle_tx.send(handle).unwrap();
                    release_rx.recv().unwrap();
                },
            );
        });
        ManagedTestThread {
            handle: handle_rx.recv().unwrap(),
            release_tx,
            join: Some(join),
        }
    }

    fn pending_signal_bits(handle: &super::ThreadHandle) -> u32 {
        let inner = handle.0.lock().unwrap();
        let inner = inner.as_ref().unwrap();
        let tls = unsafe { &*inner.tls.0 };
        tls.pending_host_signals.load(Ordering::SeqCst)
    }

    struct TimerCaptureShim {
        scope: usize,
        process_id: ProcessId,
        observed_target: std::sync::Arc<std::sync::Mutex<Option<super::SignalProcessKey>>>,
    }

    impl litebox::shim::EnterShim for TimerCaptureShim {
        type ExecutionContext = litebox_common_linux::ExecutionContext;

        fn init(&self, _ctx: &mut Self::ExecutionContext) -> litebox::shim::ContinueOperation {
            let platform = WindowsUserland::new(None);
            let timer = <WindowsUserland as litebox::platform::TimerProvider>::create_timer(
                platform,
                litebox_common_linux::signal::Signal::SIGUSR1,
            )
            .unwrap();
            let target = match &timer._ctx.target {
                super::SignalTarget::Process(key) => Some(*key),
                super::SignalTarget::Thread(_) => None,
            };
            *self.observed_target.lock().unwrap() = target;
            litebox::shim::ContinueOperation::Terminate
        }

        fn syscall(&self, _ctx: &mut Self::ExecutionContext) -> litebox::shim::ContinueOperation {
            litebox::shim::ContinueOperation::Terminate
        }

        fn exception(
            &self,
            _ctx: &mut Self::ExecutionContext,
            _info: &litebox::shim::ExceptionInfo,
        ) -> litebox::shim::ContinueOperation {
            litebox::shim::ContinueOperation::Terminate
        }

        fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> litebox::shim::ContinueOperation {
            litebox::shim::ContinueOperation::Terminate
        }

        fn process_id(&self) -> Option<ProcessId> {
            Some(self.process_id)
        }

        fn signal_target_scope(&self) -> Option<usize> {
            Some(self.scope)
        }
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
    fn test_raw_mutex_wake_one_reports_unknown() {
        let mutex = super::RawMutex {
            inner: AtomicU32::new(0),
        };

        assert!(!mutex.wake_one());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = WindowsUserland::new(None);
        let reserved_pages: Vec<_> =
            <WindowsUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are not empty
        assert!(!reserved_pages.is_empty(), "No reserved pages found");

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }

    #[test]
    fn test_partition_range_for_suggested_range() {
        let slot0 = super::partition_range_for_suggested_range(0..0x1000);
        assert_eq!(slot0.start, super::va_partitions::VA_MIN);
        assert_eq!(slot0.end, super::va_partitions::PARTITION_SIZE);

        let slot2_anchor = 2 * super::va_partitions::PARTITION_SIZE + 0x23_000;
        let slot2 =
            super::partition_range_for_suggested_range(slot2_anchor..slot2_anchor + 0x4_000);
        assert_eq!(slot2.start, 2 * super::va_partitions::PARTITION_SIZE);
        assert_eq!(slot2.end, 3 * super::va_partitions::PARTITION_SIZE);
    }

    #[test]
    fn tls_state_tracks_guest_va_range() {
        super::WindowsUserland::set_guest_va_range(0x2_0000_0000..0x2_0001_0000);
        let tls = super::TlsState::new();
        assert!(tls.guest_va_contains(0x2_0000_1000));
        assert!(!tls.guest_va_contains(0x1_FFFF_F000));
        assert!(!tls.guest_va_contains(0x2_0001_0000));
        super::WindowsUserland::set_guest_va_range(0..0);
    }

    #[test]
    fn test_page_provider() {
        let platform = WindowsUserland::new(None);
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        // Allocate some pages: it should reserve `system_allocation_granularity` bytes but only commit 0x1000 bytes
        let addr = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            0..0x1000,
            MemoryRegionPermissions::WRITE,
            false,
            true,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_eq!(
            collect_regions(addr..addr + system_allocation_granularity),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + system_allocation_granularity,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
            ]
        );

        assert!(system_allocation_granularity >= 0x1_0000);
        // We should be able to allocate [addr + 0x8000, addr + 0x1_0000)
        let addr2 = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            (addr + 0x8000)..(addr + 0x1_0000),
            MemoryRegionPermissions::WRITE,
            false,
            true,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        // Even though `fixed_address` is false, we should still get the requested address if it's free.
        assert_eq!(addr2, addr + 0x8000);
        assert_eq!(
            collect_regions(addr..addr + 0x1_0000),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + 0x8000,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
                (
                    addr + 0x8000..addr + 0x1_0000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
            ]
        );

        // Try to allocate [addr + 0x4000, addr + 0x1_0000), which overlaps with existing committed pages.
        // OS should allocate a new region instead of the requested one (as `fixed_address` is false)
        let addr3 = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            (addr + 0x4000)..(addr + 0x1_0000),
            MemoryRegionPermissions::WRITE,
            false,
            true,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_ne!(addr3, addr + 0x4000);
    }

    #[test]
    fn test_init_task_uses_internal_pid_namespace_and_host_credentials() {
        let platform = WindowsUserland::new(None);
        let task = platform.init_task();
        let identity = WindowsUserland::current_process_unix_identity();
        assert_eq!(
            task.pid,
            i32::try_from(litebox::process::ProcessId::INIT.0).unwrap()
        );
        assert_eq!(task.ppid, 0);
        assert_eq!(task.uid, identity.uid);
        assert_eq!(task.euid, identity.uid);
        assert_eq!(task.gid, identity.gid);
        assert_eq!(task.egid, identity.gid);
    }

    #[test]
    fn test_user_page_fault_grows_stack_mapping() {
        let platform = WindowsUserland::new(None);
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        assert!(system_allocation_granularity >= 0xA000);

        let base = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            0..0x1000,
            MemoryRegionPermissions::WRITE,
            false,
            true,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();

        let litebox = litebox::LiteBox::new(platform);
        let page_manager = PageManager::<WindowsUserland, 4096>::new(
            &litebox,
            <WindowsUserland as PageManagementProvider<4096>>::TASK_ADDR_MIN
                ..<WindowsUserland as PageManagementProvider<4096>>::TASK_ADDR_MAX,
        );

        let stack_start = base + 0x8000;
        // SAFETY: The test allocates this range immediately above a freshly
        // reserved region and requests a fixed, non-replacing stack mapping.
        let stack_ptr = unsafe {
            page_manager.create_stack_pages(
                Some(NonZeroAddress::new(stack_start).unwrap()),
                NonZeroPageSize::new(0x2000).unwrap(),
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            )
        }
        .unwrap();
        assert_eq!(stack_ptr.as_usize(), stack_start);

        let grow_page = stack_start - 0x1000;
        assert_eq!(
            collect_regions(grow_page..stack_start),
            vec![(grow_page..stack_start, super::Win32_Memory::MEM_RESERVE)]
        );

        // SAFETY: `grow_page` lies inside the reserved grow-down runway for the
        // stack mapping created above, and the synthesized write fault code
        // matches the access we are testing.
        unsafe {
            page_manager.handle_page_fault(grow_page, 0x6).unwrap();
        }

        assert_eq!(
            page_manager.get_memory_permissions(
                NonZeroAddress::new(grow_page).unwrap(),
                NonZeroPageSize::new(0x1000).unwrap(),
            ),
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE)
        );
        assert_eq!(
            collect_regions(grow_page..stack_start),
            vec![(grow_page..stack_start, super::Win32_Memory::MEM_COMMIT)]
        );

        // SAFETY: `base` is the allocation base returned by `allocate_pages`,
        // so releasing it with `MEM_RELEASE` and size 0 tears down the full
        // reserved region that this test created.
        let ok = unsafe {
            super::VirtualFree(
                base as *mut core::ffi::c_void,
                0,
                super::Win32_Memory::MEM_RELEASE,
            ) != 0
        };
        if !ok {
            // SAFETY: This reads the thread-local Win32 error code immediately
            // after the failing API call above.
            let err = unsafe { super::GetLastError() };
            panic!("VirtualFree(MEM_RELEASE) failed: {err}");
        }
    }

    // -- Step 3.2: error-code synthesis tests --

    #[test]
    fn test_synthesize_pf_error_code() {
        use super::synthesize_pf_error_code;

        // Write to committed (present) page → CoW case: bits 0+1+2 = 0b111 = 0x7
        assert_eq!(synthesize_pf_error_code(true, 1), 0x7);
        // Shim CoW check: (error_code & 0x3) == 0x3
        assert_eq!(synthesize_pf_error_code(true, 1) & 0x3, 0x3);

        // Write to unmapped page: bits 1+2 = 0b110 = 0x6
        assert_eq!(synthesize_pf_error_code(false, 1), 0x6);
        assert_ne!(synthesize_pf_error_code(false, 1) & 0x3, 0x3);

        // Read, committed page: bits 0+2 = 0b101 = 0x5
        assert_eq!(synthesize_pf_error_code(true, 0), 0x5);

        // Read, unmapped page: bit 2 only = 0b100 = 0x4
        assert_eq!(synthesize_pf_error_code(false, 0), 0x4);

        // DEP, committed page: bits 0+4+2 = 0x15
        assert_eq!(synthesize_pf_error_code(true, 8), 0x15);

        // DEP, uncommitted page: bits 4+2 = 0x14
        assert_eq!(synthesize_pf_error_code(false, 8), 0x14);
    }

    #[test]
    fn test_access_error_treats_present_dep_fault_as_unrecoverable() {
        let exec_flags =
            litebox::mm::linux::VmFlags::VM_READ | litebox::mm::linux::VmFlags::VM_EXEC;
        assert!(
            !<WindowsUserland as litebox::mm::linux::VmemPageFaultHandler>::access_error(
                0x14, exec_flags
            )
        );
        assert!(
            <WindowsUserland as litebox::mm::linux::VmemPageFaultHandler>::access_error(
                0x15, exec_flags
            )
        );
    }

    #[test]
    fn test_is_page_committed_states() {
        use super::is_page_committed;

        // Committed page → true
        let addr = unsafe {
            super::VirtualAlloc2(
                super::GetCurrentProcess(),
                core::ptr::null_mut(),
                0x1000,
                super::Win32_Memory::MEM_COMMIT | super::Win32_Memory::MEM_RESERVE,
                super::Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!addr.is_null());
        assert!(is_page_committed(addr as usize));

        // Change to read-only — still committed
        let mut old_protect = 0u32;
        let ok = unsafe {
            super::VirtualProtect(
                addr,
                0x1000,
                super::Win32_Memory::PAGE_READONLY,
                &mut old_protect,
            ) != 0
        };
        assert!(ok);
        assert!(is_page_committed(addr as usize));

        // Free the page → not committed
        let ok = unsafe { super::VirtualFree(addr, 0, super::Win32_Memory::MEM_RELEASE) != 0 };
        assert!(ok);
        assert!(!is_page_committed(addr as usize));

        // Reserved-only (no commit) → not committed
        let reserved = unsafe {
            super::VirtualAlloc2(
                super::GetCurrentProcess(),
                core::ptr::null_mut(),
                0x1000,
                super::Win32_Memory::MEM_RESERVE,
                super::Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!reserved.is_null());
        assert!(!is_page_committed(reserved as usize));
        let ok = unsafe { super::VirtualFree(reserved, 0, super::Win32_Memory::MEM_RELEASE) != 0 };
        assert!(ok);
    }

    // -- Step 3.3: VirtualProtect round-trip tests --

    #[test]
    fn test_virtualprotect_cow_roundtrip() {
        let addr = unsafe {
            super::VirtualAlloc2(
                super::GetCurrentProcess(),
                core::ptr::null_mut(),
                0x1000,
                super::Win32_Memory::MEM_COMMIT | super::Win32_Memory::MEM_RESERVE,
                super::Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!addr.is_null());

        let mut old_protect = 0u32;

        // RW → RO
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_READONLY,
                    &mut old_protect,
                )
            },
            0
        );
        // RO → RW
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_READWRITE,
                    &mut old_protect,
                )
            },
            0
        );

        // XRW → XR
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            },
            0
        );
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_EXECUTE_READ,
                    &mut old_protect,
                )
            },
            0
        );
        // XR → XRW
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            },
            0
        );

        assert_ne!(
            unsafe { super::VirtualFree(addr, 0, super::Win32_Memory::MEM_RELEASE) },
            0
        );
    }

    #[test]
    fn test_create_timer_captures_signal_process_key_from_shim_scope() {
        let observed_target = std::sync::Arc::new(std::sync::Mutex::new(None));
        let shim = TimerCaptureShim {
            scope: 7,
            process_id: ProcessId(9),
            observed_target: observed_target.clone(),
        };
        let mut ctx = litebox_common_linux::ExecutionContext::default();

        unsafe {
            super::run_thread_ref(&shim, &mut ctx);
        }

        assert_eq!(
            *observed_target.lock().unwrap(),
            Some(super::SignalProcessKey {
                scope: 7,
                process_id: ProcessId(9),
            })
        );
    }

    #[test]
    fn test_threadpool_timer_callback_targets_own_process() {
        let _guard = SIGNAL_ROUTING_TEST_LOCK.lock().unwrap();
        let process_a = spawn_managed_test_thread(1, ProcessId(1));
        let process_b = spawn_managed_test_thread(2, ProcessId(1));
        let signal = litebox_common_linux::signal::Signal::SIGUSR1;
        let bit = 1u32 << (signal.as_i32() - 1);
        let ctx = super::TimerCallbackContext {
            signal,
            target: super::SignalTarget::Process(super::SignalProcessKey {
                scope: 2,
                process_id: ProcessId(1),
            }),
        };

        unsafe {
            super::threadpool_timer_callback(0, (&raw const ctx).cast_mut().cast(), 0);
        }

        assert_eq!(pending_signal_bits(&process_a.handle), 0);
        assert_eq!(pending_signal_bits(&process_b.handle), bit);
    }

    #[test]
    fn test_ctrl_c_handler_signals_each_active_process() {
        let _guard = SIGNAL_ROUTING_TEST_LOCK.lock().unwrap();
        let process_a = spawn_managed_test_thread(1, ProcessId(1));
        let process_b = spawn_managed_test_thread(2, ProcessId(1));
        let sigint = litebox_common_linux::signal::Signal::SIGINT;
        let bit = 1u32 << (sigint.as_i32() - 1);

        assert_eq!(
            unsafe { super::ctrl_c_handler(windows_sys::Win32::System::Console::CTRL_C_EVENT) },
            1
        );

        assert_eq!(pending_signal_bits(&process_a.handle), bit);
        assert_eq!(pending_signal_bits(&process_b.handle), bit);
    }
}
