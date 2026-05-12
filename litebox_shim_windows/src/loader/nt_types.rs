// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows PEB/TEB layout types used by the Windows shim.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ProcessEnvironmentBlock {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    pub padding_0: [u8; 4],
    pub mutant: usize,
    pub image_base_address: usize,
    pub ldr: usize,
    /// Pointer to [`RtlUserProcessParameters`].
    pub process_parameters: usize,
    pub sub_system_data: usize,
    pub process_heap: usize,
    pub fast_peb_lock: usize,
    pub atl_thunk_s_list_ptr: usize,
    pub ifeo_key: usize,
    pub cross_process_flags: u32,
    pub padding_1: [u8; 4],
    pub kernel_callback_table: usize,
    pub system_reserved: u32,
    pub atl_thunk_s_list_ptr_32: u32,
    pub api_set_map: usize,
    pub tls_expansion_counter: u32,
    pub padding_2: [u8; 4],
    pub tls_bitmap: usize,
    pub tls_bitmap_bits: [u32; 2],
    pub read_only_shared_memory_base: usize,
    pub shared_data: usize,
    pub read_only_static_server_data: usize,
    pub ansi_code_page_data: usize,
    pub oem_code_page_data: usize,
    pub unicode_case_table_data: usize,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: u64,
    pub heap_segment_commit: u64,
    pub heap_de_commit_total_free_threshold: u64,
    pub heap_de_commit_free_block_threshold: u64,
    pub number_of_heaps: u32,
    pub maximum_number_of_heaps: u32,
    pub process_heaps: usize,
    pub gdi_shared_handle_table: usize,
    pub process_starter_helper: usize,
    pub gdi_dc_attribute_list: u32,
    pub padding_3: [u8; 4],
    pub loader_lock: usize,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_csd_version: u16,
    pub os_platform_id: u32,
    pub image_subsystem: u32,
    pub image_subsystem_major_version: u32,
    pub image_subsystem_minor_version: u32,
    pub padding_4: [u8; 4],
    pub active_process_affinity_mask: u64,
    pub gdi_handle_buffer: [u32; 60],
    pub post_process_init_routine: usize,
    pub tls_expansion_bitmap: usize,
    pub tls_expansion_bitmap_bits: [u32; 32],
    pub session_id: u32,
    pub padding_5: [u8; 4],
    pub app_compat_flags: u64,
    pub app_compat_flags_user: u64,
    pub p_shim_data: usize,
    pub app_compat_info: usize,
    pub csd_version: UnicodeString,
    pub activation_context_data: usize,
    pub process_assembly_storage_map: usize,
    pub system_default_activation_context_data: usize,
    pub system_assembly_storage_map: usize,
    pub minimum_stack_commit: u64,
    pub spare_pointers: [usize; 2],
    pub patch_loader_data: usize,
    pub chpe_v2_process_info: usize,
    pub app_model_feature_state: u32,
    pub spare_ulongs: [u32; 2],
    pub active_code_page: u16,
    pub oem_code_page: u16,
    pub use_case_mapping: u16,
    pub unused_nls_field: u16,
    pub padding_6a: [u8; 4],
    pub wer_registration_data: usize,
    pub wer_ship_assert_ptr: usize,
    pub ec_code_bit_map: usize,
    pub p_image_header_hash: usize,
    pub tracing_flags: u32,
    pub padding_6: [u8; 4],
    pub csr_server_read_only_shared_memory_base: u64,
    pub tpp_workerp_list_lock: u64,
    pub tpp_workerp_list: ListEntry,
    pub wait_on_address_hash_table: [usize; 128],
    pub telemetry_coverage_header: usize,
    pub cloud_file_flags: u32,
    pub cloud_file_diag_flags: u32,
    pub placeholder_compatibility_mode: i8,
    pub placeholder_compatibility_mode_reserved: [i8; 7],
    pub leap_second_data: usize,
    pub leap_second_flags: u32,
    pub nt_global_flag_2: u32,
    pub extended_feature_disable_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct NtTib {
    pub exception_list: usize,
    pub stack_base: usize,
    pub stack_limit: usize,
    pub sub_system_tib: usize,
    pub fiber_data_or_version: usize,
    pub arbitrary_user_pointer: usize,
    pub self_pointer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ActivationContextStack {
    _reserved: [u8; 0x28],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GdiTebBatch {
    _reserved: [u8; 0x4e8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub padding_0: [u8; 4],
    pub buffer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct CurDir {
    pub dos_path: UnicodeString,
    pub handle: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct RtlDriveLetterCurdir {
    /// Per-drive current-directory flags.
    pub flags: u16,
    /// Length of the drive current-directory entry.
    pub length: u16,
    /// Timestamp associated with this drive current-directory entry.
    pub time_stamp: u32,
    /// DOS path for this drive's current directory.
    pub dos_path: UnicodeString,
}

#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct RtlUserProcFlags(u32);

impl RtlUserProcFlags {
    /// Pointers in the process-parameter block are absolute addresses.
    pub const NORMALIZED: Self = Self(0x0000_0001);
    pub const PROFILE_USER: Self = Self(0x0000_0002);
    pub const PROFILE_KERNEL: Self = Self(0x0000_0004);
    pub const PROFILE_SERVER: Self = Self(0x0000_0008);
    pub const UNKNOWN: Self = Self(0x0000_0010);
    /// Reserve low address space at process creation.
    pub const RESERVE_1MB: Self = Self(0x0000_0020);
    /// Reserve low address space at process creation.
    pub const RESERVE_16MB: Self = Self(0x0000_0040);
    pub const CASE_SENSITIVE: Self = Self(0x0000_0080);
    pub const DISABLE_HEAP_DECOMMIT: Self = Self(0x0000_0100);
    pub const PROCESS_OR_1: Self = Self(0x0000_0200);
    pub const PROCESS_OR_2: Self = Self(0x0000_0400);
    pub const DLL_REDIRECTION_LOCAL: Self = Self(0x0000_1000);
    /// An application manifest was detected during process creation.
    pub const APP_MANIFEST_PRESENT: Self = Self(0x0000_2000);
    /// The corresponding Image File Execution Options key was missing at process creation.
    pub const IMAGE_KEY_MISSING: Self = Self(0x0000_4000);
    /// System-global IFEO development override support is enabled.
    pub const DEV_OVERRIDE_ENABLED: Self = Self(0x0000_8000);
    pub const OPTIN_PROCESS: Self = Self(0x0002_0000);
    pub const SESSION_OWNER: Self = Self(0x0004_0000);
    pub const HANDLE_USER_CALLBACK_EXCEPTIONS: Self = Self(0x0008_0000);
    pub const PROTECTED_PROCESS: Self = Self(0x0040_0000);
    pub const NO_IMAGE_EXPANSION_MITIGATION: Self = Self(0x0200_0000);
    pub const APPX_LOADER_ALTERNATE_FORWARDER: Self = Self(0x0400_0000);
    pub const APPX_GLOBAL_OVERRIDE: Self = Self(0x0800_0000);
    /// Allow the loader to use OneCore API-set forwarders when resolving imports.
    pub const ONECORE_FORWARDERS_ENABLED: Self = Self(0x2000_0000);
    /// Opt back in to the normal `ExitProcess` path that detaches DLLs on exit.
    pub const EXIT_PROCESS_NORMAL: Self = Self(0x4000_0000);
    pub const SECURE_PROCESS: Self = Self(0x8000_0000);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for RtlUserProcFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for RtlUserProcFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Memory layout of this struct:
///
/// ```text
/// +-------------------------------+
/// | RTL_USER_PROCESS_PARAMETERS   |
/// | fixed-size struct             |
/// +-------------------------------+
/// | CurrentDirectory.DosPath      |
/// | (string buffer)               |
/// +-------------------------------+
/// | DllPath                       |
/// +-------------------------------+
/// | ImagePathName                 |
/// +-------------------------------+
/// | CommandLine                   |
/// +-------------------------------+
/// | WindowTitle                   |
/// +-------------------------------+
/// | DesktopInfo                   |
/// +-------------------------------+
/// | ShellInfo                     |
/// +-------------------------------+
/// | RuntimeData                   |
/// +-------------------------------+
/// | RedirectionDllName            |
/// +-------------------------------+
/// ```
///
/// See <https://ntdoc.m417z.com/rtl_user_process_parameters> for details on the fields of this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct RtlUserProcessParameters {
    /// Total allocated size of this process-parameter buffer, in bytes.
    pub maximum_length: u32,
    /// Size of the process-parameter block, including any inline variable-length strings.
    pub length: u32,
    /// Process-parameter flags.
    pub flags: RtlUserProcFlags,
    /// Debug flags associated with these process parameters.
    pub debug_flags: u32,
    /// Console session handle, inherited or derived from process creation options.
    pub console_handle: usize,
    /// Console behavior flags, such as ignoring Ctrl+C requests.
    pub console_flags: u32,
    /// Reserved alignment padding.
    pub padding_0: [u8; 4],
    /// Standard input handle from `STARTUPINFO.hStdInput`.
    pub standard_input: usize,
    /// Standard output handle from `STARTUPINFO.hStdOutput`.
    pub standard_output: usize,
    /// Standard error handle from `STARTUPINFO.hStdError`.
    pub standard_error: usize,
    /// Current directory path and handle.
    pub current_directory: CurDir,
    /// Semicolon-separated DOS-style DLL search paths.
    pub dll_path: UnicodeString,
    /// Full DOS-style path to the executable image.
    pub image_path_name: UnicodeString,
    /// Command line string passed to the process.
    pub command_line: UnicodeString,
    /// Pointer to the separately allocated environment block.
    pub environment: usize,
    /// Initial window X position when `window_flags` requests a position.
    pub starting_x: u32,
    /// Initial window Y position when `window_flags` requests a position.
    pub starting_y: u32,
    /// Initial window width when `window_flags` requests a size.
    pub count_x: u32,
    /// Initial window height when `window_flags` requests a size.
    pub count_y: u32,
    /// Initial console screen-buffer width in character cells.
    pub count_chars_x: u32,
    /// Initial console screen-buffer height in character cells.
    pub count_chars_y: u32,
    /// Initial console text/background color attributes.
    pub fill_attribute: u32,
    /// `STARTUPINFO` flags describing which startup fields are valid.
    pub window_flags: u32,
    /// `ShowWindow` value used when `window_flags` includes `STARTF_USESHOWWINDOW`.
    pub show_window_flags: u32,
    /// Reserved alignment padding.
    pub padding_1: [u8; 4],
    /// Console window title, shortcut path, or AppUserModelID depending on `window_flags`.
    pub window_title: UnicodeString,
    /// Window station and desktop name, such as `WinSta0\Default`.
    pub desktop_info: UnicodeString,
    /// Startup shell data corresponding to `STARTUPINFO.lpReserved`.
    pub shell_info: UnicodeString,
    /// Runtime data corresponding to `STARTUPINFO.lpReserved2` and `cbReserved2`.
    pub runtime_data: UnicodeString,
    /// Per-drive current-directory entries for the 32 DOS drive letters.
    pub current_directories: [RtlDriveLetterCurdir; 32],
    /// Allocated size of the environment block, in bytes.
    pub environment_size: u64,
    /// Environment version incremented when environment strings change.
    pub environment_version: u64,
    /// Package dependency metadata pointer.
    pub package_dependency_data: usize,
    /// Console process group identifier used to scope control-signal delivery.
    pub process_group_id: u32,
    /// Requested worker-thread count for parallel DLL loading.
    pub loader_threads: u32,
    /// DLL path used for packaged-app import redirection.
    pub redirection_dll_name: UnicodeString,
    /// Heap partition name.
    pub heap_partition_name: UnicodeString,
    /// Pointer to default thread-pool CPU-set masks.
    pub default_threadpool_cpu_set_masks: usize,
    /// Number of default thread-pool CPU-set masks.
    pub default_threadpool_cpu_set_mask_count: u32,
    /// Maximum default thread-pool thread count.
    pub default_threadpool_thread_maximum: u32,
    /// Heap memory type mask.
    pub heap_memory_type_mask: u32,
    /// Reserved tail padding.
    pub padding_2: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ListEntry {
    pub flink: usize,
    pub blink: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct Guid {
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ProcessorNumber {
    pub group: u16,
    pub number: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GroupAffinity {
    pub mask: usize,
    pub group: u16,
    pub reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ThreadEnvironmentBlock {
    pub nt_tib: NtTib,
    pub environment_pointer: usize,
    pub client_id: ClientId,
    pub active_rpc_handle: usize,
    pub thread_local_storage_pointer: usize,
    /// Pointer to [`ProcessEnvironmentBlock`].
    pub process_environment_block: usize,
    pub last_error_value: u32,
    pub count_of_owned_critical_sections: u32,
    pub csr_client_thread: usize,
    pub win_32_thread_info: usize,
    pub user_32_reserved: [u32; 26],
    pub user_reserved: [u32; 5],
    pub padding_user_reserved: [u8; 4],
    pub wow_32_reserved: usize,
    pub current_locale: u32,
    pub fp_software_status_register: u32,
    pub reserved_for_debugger_instrumentation: [usize; 16],
    pub system_reserved_1: [usize; 25],
    pub heap_fls_data: usize,
    pub rng_state: [u64; 4],
    pub placeholder_compatibility_mode: i8,
    pub placeholder_hydration_always_explicit: u8,
    pub placeholder_reserved: [i8; 10],
    pub proxied_process_id: u32,
    pub activation_stack: ActivationContextStack,
    pub working_on_behalf_ticket: [u8; 8],
    pub exception_code: i32,
    pub padding_0: [u8; 4],
    pub activation_context_stack_pointer: usize,
    pub instrumentation_callback_sp: u64,
    pub instrumentation_callback_previous_pc: u64,
    pub instrumentation_callback_previous_sp: u64,
    pub tx_fs_context: u32,
    pub instrumentation_callback_disabled: u8,
    pub unaligned_load_store_exceptions: u8,
    pub padding_1: [u8; 2],
    pub gdi_teb_batch: GdiTebBatch,
    pub real_client_id: ClientId,
    pub gdi_cached_process_handle: usize,
    pub gdi_client_pid: u32,
    pub gdi_client_tid: u32,
    pub gdi_thread_local_info: usize,
    pub win_32_client_info: [u64; 62],
    pub gl_dispatch_table: [usize; 233],
    pub gl_reserved_1: [u64; 29],
    pub gl_reserved_2: usize,
    pub gl_section_info: usize,
    pub gl_section: usize,
    pub gl_table: usize,
    pub gl_current_rc: usize,
    pub gl_context: usize,
    pub last_status_value: u32,
    pub padding_2: [u8; 4],
    pub static_unicode_string: UnicodeString,
    pub static_unicode_buffer: [u16; 261],
    pub padding_3: [u8; 6],
    pub deallocation_stack: usize,
    pub tls_slots: [usize; 64],
    pub tls_links: ListEntry,
    pub vdm: usize,
    pub reserved_for_nt_rpc: usize,
    pub dbg_ss_reserved: [usize; 2],
    pub hard_error_mode: u32,
    pub padding_4: [u8; 4],
    pub instrumentation: [usize; 11],
    pub activity_id: Guid,
    pub sub_process_tag: usize,
    pub perflib_data: usize,
    pub etw_trace_data: usize,
    pub win_sock_data: usize,
    pub gdi_batch_count: u32,
    pub ideal_processor_value: u32,
    pub guaranteed_stack_bytes: u32,
    pub padding_5: [u8; 4],
    pub reserved_for_perf: usize,
    pub reserved_for_ole: usize,
    pub waiting_on_loader_lock: u32,
    pub padding_6: [u8; 4],
    pub saved_priority_state: usize,
    pub reserved_for_code_coverage: u64,
    pub thread_pool_data: usize,
    pub tls_expansion_slots: usize,
    pub chpe_v_2_cpu_area_info: usize,
    pub unused: usize,
    pub mui_generation: u32,
    pub is_impersonating: u32,
    pub nls_cache: usize,
    pub p_shim_data: usize,
    pub heap_data: u32,
    pub padding_7: [u8; 4],
    pub current_transaction_handle: usize,
    pub active_frame: usize,
    pub fls_data: usize,
    pub preferred_languages: usize,
    pub user_pref_languages: usize,
    pub merged_pref_languages: usize,
    pub mui_impersonation: u32,
    pub cross_teb_flags: u16,
    pub same_teb_flags: u16,
    pub txn_scope_enter_callback: usize,
    pub txn_scope_exit_callback: usize,
    pub txn_scope_context: usize,
    pub lock_count: u32,
    pub wow_teb_offset: i32,
    pub resource_ret_value: usize,
    pub reserved_for_wdf: usize,
    pub reserved_for_crt: u64,
    pub effective_container_id: Guid,
    pub last_sleep_counter: u64,
    pub spin_call_count: u32,
    pub padding_8: [u8; 4],
    pub extended_feature_disable_mask: u64,
    pub scheduler_shared_data_slot: usize,
    pub heap_walk_context: usize,
    pub primary_group_affinity: GroupAffinity,
    pub rcu: [u32; 2],
}

const _: [(); 0x1878] = [(); core::mem::size_of::<ThreadEnvironmentBlock>()];
const _: [(); 0x7d0] = [(); core::mem::size_of::<ProcessEnvironmentBlock>()];
const _: [(); 0x38] = [(); core::mem::size_of::<NtTib>()];
const _: [(); 0x18] = [(); core::mem::size_of::<CurDir>()];
const _: [(); 0x18] = [(); core::mem::size_of::<RtlDriveLetterCurdir>()];
const _: [(); 0x448] = [(); core::mem::size_of::<RtlUserProcessParameters>()];
