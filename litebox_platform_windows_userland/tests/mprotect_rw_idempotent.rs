// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use litebox::{
    LiteBox,
    mm::{
        PageManager,
        linux::{CreatePagesFlags, NonZeroPageSize, PAGE_SIZE},
    },
    platform::{RawConstPointer as _, RawMutPointer as _},
};
use litebox_common_linux::{ProtFlags, UserPtrMut};
use litebox_platform_windows_userland::WindowsUserland;

#[test]
fn anonymous_rw_mapping_stays_writable_after_idempotent_mprotect() {
    let platform = WindowsUserland::new();
    let litebox = LiteBox::new(platform);
    let pm = PageManager::<WindowsUserland, PAGE_SIZE>::new(&litebox);
    let len = NonZeroPageSize::new(PAGE_SIZE).unwrap();

    let raw = unsafe {
        pm.create_writable_pages(None, len, CreatePagesFlags::empty(), |_| Ok(0))
    }
    .expect("initial anonymous RW mapping must succeed");
    let addr = UserPtrMut::from_platform_ptr::<WindowsUserland>(raw);

    addr.copy_from_slice::<WindowsUserland>(0, b"before")
        .expect("fresh RW mapping must be writable before mprotect");

    litebox_common_linux::mm::sys_mprotect(
        &pm,
        addr,
        PAGE_SIZE,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
    )
    .expect("idempotent mprotect(RW) must succeed");

    addr.copy_from_slice::<WindowsUserland>(0, b"after!")
        .expect("RW mapping must remain writable after mprotect(RW)");
    let bytes = addr
        .to_owned_slice::<WindowsUserland>(6)
        .expect("RW mapping must remain readable after mprotect(RW)");
    assert_eq!(&*bytes, b"after!");

    // Repeat the same transition: bionic's LinkerBlockAllocator can protect
    // already-RW allocator pages more than once as it grows allocation batches.
    litebox_common_linux::mm::sys_mprotect(
        &pm,
        addr,
        PAGE_SIZE,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
    )
    .expect("repeated idempotent mprotect(RW) must succeed");
    addr.copy_from_slice::<WindowsUserland>(0, b"again!")
        .expect("RW mapping must remain writable after repeated mprotect(RW)");

    unsafe { pm.remove_pages(raw, PAGE_SIZE) }.expect("test mapping cleanup must succeed");
}
