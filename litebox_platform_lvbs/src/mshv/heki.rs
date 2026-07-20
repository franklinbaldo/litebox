// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::mshv::HvPageProtFlags;

pub use litebox_common_lvbs::{
    HekiKdataType, HekiKernelInfo, HekiKernelSymbol, HekiKexecType, HekiPage, HekiPatch,
    HekiPatchInfo, HekiRange, MemAttr, ModMemType, POKE_MAX_OPCODE_SIZE,
};

pub(crate) fn mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();

    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }

    flags
}

pub fn mod_mem_type_to_mem_attr(mod_mem_type: ModMemType) -> MemAttr {
    let mut mem_attr = MemAttr::empty();

    match mod_mem_type {
        ModMemType::Text | ModMemType::InitText => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_EXEC, true);
        }
        ModMemType::Data | ModMemType::RoAfterInit | ModMemType::InitData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_WRITE, true);
        }
        ModMemType::RoData | ModMemType::InitRoData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
        }
        _ => {}
    }

    mem_attr
}
