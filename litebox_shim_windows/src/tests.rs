// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::AtomicI32;
use litebox::LiteBox;
use litebox::fd::RawDescriptorStorage;
use litebox::fs::{FileSystem as _, Mode, OFlags};
use litebox::platform::TimeProvider as _;
use litebox_common_windows::loader::MappingInfo;

use crate::{
    DefaultFS, GlobalState, Process, Task, WindowsHandleStore, WindowsNlsSectionMappings,
    WindowsPageManager,
};

pub(crate) fn init_platform() {
    static PLATFORM_INIT: std::sync::Once = std::sync::Once::new();
    PLATFORM_INIT.call_once(|| {
        let platform = crate::Platform::new();
        litebox_platform_multiplex::set_platform(platform);
    });
}

pub(crate) fn test_task() -> Task<DefaultFS> {
    test_task_with_process(0, 1)
}

pub(crate) fn test_task_with_process(peb_address: usize, cookie: u32) -> Task<DefaultFS> {
    test_task_with_nls_files_and_process(&[], peb_address, cookie)
}

pub(crate) fn test_task_with_nls_files(nls_files: &[(&str, &[u8])]) -> Task<DefaultFS> {
    test_task_with_nls_files_and_process(nls_files, 0, 1)
}

fn test_task_with_nls_files_and_process(
    nls_files: &[(&str, &[u8])],
    peb_address: usize,
    cookie: u32,
) -> Task<DefaultFS> {
    init_platform();
    let platform = litebox_platform_multiplex::platform();
    let litebox = LiteBox::new(platform);
    let page_manager = WindowsPageManager::new(&litebox);
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(&litebox);
    in_mem_fs.with_root_privileges(|fs| {
        if !nls_files.is_empty() {
            fs.mkdir("/Windows", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .unwrap();
            fs.mkdir("/Windows/System32", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .unwrap();
        }
        for (path, bytes) in nls_files {
            let fd = fs
                .open(
                    *path,
                    OFlags::WRONLY | OFlags::CREAT,
                    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
                )
                .unwrap();
            fs.write(&fd, bytes, Some(0)).unwrap();
            fs.close(&fd).unwrap();
        }
    });
    let fs = Arc::new(crate::default_fs(
        &litebox,
        in_mem_fs,
        litebox::fs::tar_ro::FileSystem::new(&litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()),
    ));
    Task {
        global: Arc::new(GlobalState {
            platform,
            registry: crate::syscalls::registry::RegistryStore::new(&litebox),
            litebox,
            page_manager,
            qpc_boot_instant: platform.now(),
            _fs: PhantomData,
        }),
        fs,
        process: Arc::new(Process {
            mapping: MappingInfo {
                base_addr: 0,
                image_size: 0,
                entry_point: 0,
            },
            _ntdll_mapping: None,
            handles: WindowsHandleStore::new(RawDescriptorStorage::new()),
            nls_section_mappings: WindowsNlsSectionMappings::new(BTreeMap::new()),
            peb_address,
            cookie,
            exit_code: AtomicI32::new(0),
        }),
        entry_point: 0,
        stack_top: 0,
        teb_address: 0,
    }
}
