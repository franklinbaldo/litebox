// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows PEB/TEB layout types used by the Windows shim.

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ProcessEnvironmentBlock {
    pub inherited_address_space: u8,                      // +0x000
    pub read_image_file_exec_options: u8,                 // +0x001
    pub being_debugged: u8,                               // +0x002
    pub bit_field: u8,                                    // +0x003
    pub padding_0: [u8; 4],                               // +0x004
    pub mutant: usize,                                    // +0x008
    pub image_base_address: usize,                        // +0x010
    pub ldr: usize,                                       // +0x018
    pub process_parameters: usize,                        // +0x020
    pub sub_system_data: usize,                           // +0x028
    pub process_heap: usize,                              // +0x030
    pub fast_peb_lock: usize,                             // +0x038
    pub atl_thunk_s_list_ptr: usize,                      // +0x040
    pub ifeo_key: usize,                                  // +0x048
    pub cross_process_flags: u32,                         // +0x050
    pub padding_1: [u8; 4],                               // +0x054
    pub kernel_callback_table: usize,                     // +0x058
    pub system_reserved: u32,                             // +0x060
    pub atl_thunk_s_list_ptr_32: u32,                     // +0x064
    pub api_set_map: usize,                               // +0x068
    pub tls_expansion_counter: u32,                       // +0x070
    pub padding_2: [u8; 4],                               // +0x074
    pub tls_bitmap: usize,                                // +0x078
    pub tls_bitmap_bits: [u32; 2],                        // +0x080
    pub read_only_shared_memory_base: usize,              // +0x088
    pub shared_data: usize,                               // +0x090
    pub read_only_static_server_data: usize,              // +0x098
    pub ansi_code_page_data: usize,                       // +0x0a0
    pub oem_code_page_data: usize,                        // +0x0a8
    pub unicode_case_table_data: usize,                   // +0x0b0
    pub number_of_processors: u32,                        // +0x0b8
    pub nt_global_flag: u32,                              // +0x0bc
    pub critical_section_timeout: i64,                    // +0x0c0
    pub heap_segment_reserve: u64,                        // +0x0c8
    pub heap_segment_commit: u64,                         // +0x0d0
    pub heap_de_commit_total_free_threshold: u64,         // +0x0d8
    pub heap_de_commit_free_block_threshold: u64,         // +0x0e0
    pub number_of_heaps: u32,                             // +0x0e8
    pub maximum_number_of_heaps: u32,                     // +0x0ec
    pub process_heaps: usize,                             // +0x0f0
    pub gdi_shared_handle_table: usize,                   // +0x0f8
    pub process_starter_helper: usize,                    // +0x100
    pub gdi_dc_attribute_list: u32,                       // +0x108
    pub padding_3: [u8; 4],                               // +0x10c
    pub loader_lock: usize,                               // +0x110
    pub os_major_version: u32,                            // +0x118
    pub os_minor_version: u32,                            // +0x11c
    pub os_build_number: u16,                             // +0x120
    pub os_csd_version: u16,                              // +0x122
    pub os_platform_id: u32,                              // +0x124
    pub image_subsystem: u32,                             // +0x128
    pub image_subsystem_major_version: u32,               // +0x12c
    pub image_subsystem_minor_version: u32,               // +0x130
    pub padding_4: [u8; 4],                               // +0x134
    pub active_process_affinity_mask: u64,                // +0x138
    pub gdi_handle_buffer: [u32; 60],                     // +0x140
    pub post_process_init_routine: usize,                 // +0x230
    pub tls_expansion_bitmap: usize,                      // +0x238
    pub tls_expansion_bitmap_bits: [u32; 32],             // +0x240
    pub session_id: u32,                                  // +0x2c0
    pub padding_5: [u8; 4],                               // +0x2c4
    pub app_compat_flags: u64,                            // +0x2c8
    pub app_compat_flags_user: u64,                       // +0x2d0
    pub p_shim_data: usize,                               // +0x2d8
    pub app_compat_info: usize,                           // +0x2e0
    pub csd_version: UnicodeString,                       // +0x2e8
    pub activation_context_data: usize,                   // +0x2f8
    pub process_assembly_storage_map: usize,              // +0x300
    pub system_default_activation_context_data: usize,    // +0x308
    pub system_assembly_storage_map: usize,               // +0x310
    pub minimum_stack_commit: u64,                        // +0x318
    pub spare_pointers: [usize; 2],                       // +0x320
    pub patch_loader_data: usize,                         // +0x330
    pub chpe_v2_process_info: usize,                      // +0x338
    pub app_model_feature_state: u32,                     // +0x340
    pub spare_ulongs: [u32; 2],                           // +0x344
    pub active_code_page: u16,                            // +0x34c
    pub oem_code_page: u16,                               // +0x34e
    pub use_case_mapping: u16,                            // +0x350
    pub unused_nls_field: u16,                            // +0x352
    pub padding_6a: [u8; 4],                              // +0x354
    pub wer_registration_data: usize,                     // +0x358
    pub wer_ship_assert_ptr: usize,                       // +0x360
    pub ec_code_bit_map: usize,                           // +0x368
    pub p_image_header_hash: usize,                       // +0x370
    pub tracing_flags: u32,                               // +0x378
    pub padding_6: [u8; 4],                               // +0x37c
    pub csr_server_read_only_shared_memory_base: u64,     // +0x380
    pub tpp_workerp_list_lock: u64,                       // +0x388
    pub tpp_workerp_list: ListEntry,                      // +0x390
    pub wait_on_address_hash_table: [usize; 128],         // +0x3a0
    pub telemetry_coverage_header: usize,                 // +0x7a0
    pub cloud_file_flags: u32,                            // +0x7a8
    pub cloud_file_diag_flags: u32,                       // +0x7ac
    pub placeholder_compatibility_mode: i8,               // +0x7b0
    pub placeholder_compatibility_mode_reserved: [i8; 7], // +0x7b1
    pub leap_second_data: usize,                          // +0x7b8
    pub leap_second_flags: u32,                           // +0x7c0
    pub nt_global_flag_2: u32,                            // +0x7c4
    pub extended_feature_disable_mask: u64,               // +0x7c8
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct NtTib {
    pub exception_list: usize,         // +0x000
    pub stack_base: usize,             // +0x008
    pub stack_limit: usize,            // +0x010
    pub sub_system_tib: usize,         // +0x018
    pub fiber_data_or_version: usize,  // +0x020
    pub arbitrary_user_pointer: usize, // +0x028
    pub self_pointer: usize,           // +0x030
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
    pub nt_tib: NtTib,                                      // +0x000
    pub environment_pointer: usize,                         // +0x038
    pub client_id: ClientId,                                // +0x040
    pub active_rpc_handle: usize,                           // +0x050
    pub thread_local_storage_pointer: usize,                // +0x058
    pub process_environment_block: usize,                   // +0x060
    pub last_error_value: u32,                              // +0x068
    pub count_of_owned_critical_sections: u32,              // +0x06c
    pub csr_client_thread: usize,                           // +0x070
    pub win_32_thread_info: usize,                          // +0x078
    pub user_32_reserved: [u32; 26],                        // +0x080
    pub user_reserved: [u32; 5],                            // +0x0e8
    pub padding_user_reserved: [u8; 4],                     // +0x0fc
    pub wow_32_reserved: usize,                             // +0x100
    pub current_locale: u32,                                // +0x108
    pub fp_software_status_register: u32,                   // +0x10c
    pub reserved_for_debugger_instrumentation: [usize; 16], // +0x110
    pub system_reserved_1: [usize; 25],                     // +0x190
    pub heap_fls_data: usize,                               // +0x258
    pub rng_state: [u64; 4],                                // +0x260
    pub placeholder_compatibility_mode: i8,                 // +0x280
    pub placeholder_hydration_always_explicit: u8,          // +0x281
    pub placeholder_reserved: [i8; 10],                     // +0x282
    pub proxied_process_id: u32,                            // +0x28c
    pub activation_stack: ActivationContextStack,           // +0x290
    pub working_on_behalf_ticket: [u8; 8],                  // +0x2b8
    pub exception_code: i32,                                // +0x2c0
    pub padding_0: [u8; 4],                                 // +0x2c4
    pub activation_context_stack_pointer: usize,            // +0x2c8
    pub instrumentation_callback_sp: u64,                   // +0x2d0
    pub instrumentation_callback_previous_pc: u64,          // +0x2d8
    pub instrumentation_callback_previous_sp: u64,          // +0x2e0
    pub tx_fs_context: u32,                                 // +0x2e8
    pub instrumentation_callback_disabled: u8,              // +0x2ec
    pub unaligned_load_store_exceptions: u8,                // +0x2ed
    pub padding_1: [u8; 2],                                 // +0x2ee
    pub gdi_teb_batch: GdiTebBatch,                         // +0x2f0
    pub real_client_id: ClientId,                           // +0x7d8
    pub gdi_cached_process_handle: usize,                   // +0x7e8
    pub gdi_client_pid: u32,                                // +0x7f0
    pub gdi_client_tid: u32,                                // +0x7f4
    pub gdi_thread_local_info: usize,                       // +0x7f8
    pub win_32_client_info: [u64; 62],                      // +0x800
    pub gl_dispatch_table: [usize; 233],                    // +0x9f0
    pub gl_reserved_1: [u64; 29],                           // +0x1138
    pub gl_reserved_2: usize,                               // +0x1220
    pub gl_section_info: usize,                             // +0x1228
    pub gl_section: usize,                                  // +0x1230
    pub gl_table: usize,                                    // +0x1238
    pub gl_current_rc: usize,                               // +0x1240
    pub gl_context: usize,                                  // +0x1248
    pub last_status_value: u32,                             // +0x1250
    pub padding_2: [u8; 4],                                 // +0x1254
    pub static_unicode_string: UnicodeString,               // +0x1258
    pub static_unicode_buffer: [u16; 261],                  // +0x1268
    pub padding_3: [u8; 6],                                 // +0x1472
    pub deallocation_stack: usize,                          // +0x1478
    pub tls_slots: [usize; 64],                             // +0x1480
    pub tls_links: ListEntry,                               // +0x1680
    pub vdm: usize,                                         // +0x1690
    pub reserved_for_nt_rpc: usize,                         // +0x1698
    pub dbg_ss_reserved: [usize; 2],                        // +0x16a0
    pub hard_error_mode: u32,                               // +0x16b0
    pub padding_4: [u8; 4],                                 // +0x16b4
    pub instrumentation: [usize; 11],                       // +0x16b8
    pub activity_id: Guid,                                  // +0x1710
    pub sub_process_tag: usize,                             // +0x1720
    pub perflib_data: usize,                                // +0x1728
    pub etw_trace_data: usize,                              // +0x1730
    pub win_sock_data: usize,                               // +0x1738
    pub gdi_batch_count: u32,                               // +0x1740
    pub ideal_processor_value: u32,                         // +0x1744
    pub guaranteed_stack_bytes: u32,                        // +0x1748
    pub padding_5: [u8; 4],                                 // +0x174c
    pub reserved_for_perf: usize,                           // +0x1750
    pub reserved_for_ole: usize,                            // +0x1758
    pub waiting_on_loader_lock: u32,                        // +0x1760
    pub padding_6: [u8; 4],                                 // +0x1764
    pub saved_priority_state: usize,                        // +0x1768
    pub reserved_for_code_coverage: u64,                    // +0x1770
    pub thread_pool_data: usize,                            // +0x1778
    pub tls_expansion_slots: usize,                         // +0x1780
    pub chpe_v_2_cpu_area_info: usize,                      // +0x1788
    pub unused: usize,                                      // +0x1790
    pub mui_generation: u32,                                // +0x1798
    pub is_impersonating: u32,                              // +0x179c
    pub nls_cache: usize,                                   // +0x17a0
    pub p_shim_data: usize,                                 // +0x17a8
    pub heap_data: u32,                                     // +0x17b0
    pub padding_7: [u8; 4],                                 // +0x17b4
    pub current_transaction_handle: usize,                  // +0x17b8
    pub active_frame: usize,                                // +0x17c0
    pub fls_data: usize,                                    // +0x17c8
    pub preferred_languages: usize,                         // +0x17d0
    pub user_pref_languages: usize,                         // +0x17d8
    pub merged_pref_languages: usize,                       // +0x17e0
    pub mui_impersonation: u32,                             // +0x17e8
    pub cross_teb_flags: u16,                               // +0x17ec
    pub same_teb_flags: u16,                                // +0x17ee
    pub txn_scope_enter_callback: usize,                    // +0x17f0
    pub txn_scope_exit_callback: usize,                     // +0x17f8
    pub txn_scope_context: usize,                           // +0x1800
    pub lock_count: u32,                                    // +0x1808
    pub wow_teb_offset: i32,                                // +0x180c
    pub resource_ret_value: usize,                          // +0x1810
    pub reserved_for_wdf: usize,                            // +0x1818
    pub reserved_for_crt: u64,                              // +0x1820
    pub effective_container_id: Guid,                       // +0x1828
    pub last_sleep_counter: u64,                            // +0x1838
    pub spin_call_count: u32,                               // +0x1840
    pub padding_8: [u8; 4],                                 // +0x1844
    pub extended_feature_disable_mask: u64,                 // +0x1848
    pub scheduler_shared_data_slot: usize,                  // +0x1850
    pub heap_walk_context: usize,                           // +0x1858
    pub primary_group_affinity: GroupAffinity,              // +0x1860
    pub rcu: [u32; 2],                                      // +0x1870
}

const _: [(); 0x1878] = [(); core::mem::size_of::<ThreadEnvironmentBlock>()];
const _: [(); 0x7d0] = [(); core::mem::size_of::<ProcessEnvironmentBlock>()];
const _: [(); 0x38] = [(); core::mem::size_of::<NtTib>()];
