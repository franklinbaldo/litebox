// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MIG task subsystem emulation (subsystem base 3400).
//!
//! Handles MIG requests sent to the TASK_SELF port (0x0103) for
//! task-level operations like `task_info`.

use crate::mig::{
    MachMsgHeader, HEADER_SIZE, MACH_MSG_SUCCESS, MACH_SEND_INVALID_DEST, NDR_RECORD,
};
use crate::{ConstPtr, MutPtr, ShimFS, Task};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

/// MIG reply ID offset: reply_id = request_id + 100.
const MIG_REPLY_OFFSET: i32 = 100;

// -- task_info flavors --------------------------------------------------

/// TASK_DYLD_INFO (17) — dyld all-image-info address.
const TASK_DYLD_INFO: i32 = 17;

/// MACH_TASK_BASIC_INFO (20) — basic task info.
const MACH_TASK_BASIC_INFO: i32 = 20;

/// TASK_FLAGS_INFO (22) — task flags.
const TASK_FLAGS_INFO: i32 = 22;

/// TASK_BASIC_INFO_32 (4) — legacy 32-bit basic task info.
///
/// Note: XNU defines `TASK_BASIC_INFO_32 = 4`, but on aarch64 the
/// kernel aliases `TASK_BASIC_INFO` (5) to `TASK_BASIC_INFO_32`.
/// Some runtime code requests flavor 0 which maps to the same 32-bit
/// struct via a different constant path.  We handle both 0 and 4.
const TASK_BASIC_INFO_32: i32 = 4;

impl<FS: ShimFS> Task<FS> {
    /// Dispatch a task subsystem MIG request.
    ///
    /// Routes by `msgh_id` within the 3400..3499 range.
    pub(crate) fn mig_task(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        if hdr.msgh_id == 3418 {
            self.mig_task_info(msg_addr, hdr)
        } else {
            log_unsupported!(
                "mig_task: unhandled msgh_id={}, returning MACH_SEND_INVALID_DEST",
                hdr.msgh_id,
            );
            Ok(MACH_SEND_INVALID_DEST)
        }
    }

    /// Handle `task_info` (msgh_id=3418).
    ///
    /// Request body (after 24-byte header):
    /// - NDR record (8 bytes) at offset 24
    /// - flavor: i32 at offset 32
    /// - task_info_outCnt: i32 at offset 36
    ///
    /// Reply (non-complex, variable size):
    /// - Header (24): bits=0x12, size=variable,
    ///   remote=request.msgh_local_port, local=0, voucher=0, id=3518
    /// - NDR record (8 bytes)
    /// - RetCode: i32 = 0 (KERN_SUCCESS)
    /// - task_info_outCnt: i32 = count of i32 words returned
    /// - task_info_out: variable-length data
    fn mig_task_info(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // Read flavor from offset 32 (HEADER_SIZE + 8 bytes NDR).
        let flavor_ptr: ConstPtr<i32> = ConstPtr::from_usize(msg_addr + HEADER_SIZE + 8);
        let flavor: i32 = flavor_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

        log_unsupported!(
            "mig_task_info: flavor={flavor}, reply_port={:#x}",
            hdr.msgh_local_port,
        );

        match flavor {
            0 | TASK_BASIC_INFO_32 => self.mig_task_info_basic_32(msg_addr, hdr),
            TASK_DYLD_INFO => self.mig_task_info_dyld(msg_addr, hdr),
            MACH_TASK_BASIC_INFO => self.mig_task_info_basic(msg_addr, hdr),
            TASK_FLAGS_INFO => self.mig_task_info_flags(msg_addr, hdr),
            _ => {
                log_unsupported!(
                    "mig_task_info: unknown flavor={flavor}, returning KERN_INVALID_ARGUMENT"
                );
                // Write a minimal error reply.
                self.mig_task_info_error_reply(msg_addr, hdr, 4) // KERN_INVALID_ARGUMENT
            }
        }
    }

    /// Write a non-complex reply header + NDR + RetCode + outCnt.
    ///
    /// Returns the byte offset of the start of the data area (body_base + 16).
    fn write_task_info_reply_header(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
        data_size: usize,
        out_count: i32,
    ) -> Result<usize, Errno> {
        // Reply: Header(24) + NDR(8) + RetCode(4) + outCnt(4) + data
        #[allow(clippy::cast_possible_truncation)]
        let reply_size: u32 = (HEADER_SIZE + 8 + 4 + 4 + data_size) as u32;

        let reply_hdr = MachMsgHeader {
            msgh_bits: 0x12, // MACH_MSG_TYPE_MOVE_SEND_ONCE
            msgh_size: reply_size,
            msgh_remote_port: hdr.msgh_local_port,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: hdr.msgh_id + MIG_REPLY_OFFSET, // 3518
        };
        let hdr_ptr: MutPtr<MachMsgHeader> = MutPtr::from_usize(msg_addr);
        hdr_ptr.write_at_offset(0, reply_hdr).ok_or(Errno::EFAULT)?;

        let body_base = msg_addr + HEADER_SIZE;

        // NDR record
        let ndr_ptr: MutPtr<[u8; 8]> = MutPtr::from_usize(body_base);
        ndr_ptr.write_at_offset(0, NDR_RECORD).ok_or(Errno::EFAULT)?;

        // RetCode = KERN_SUCCESS (0)
        let ret_ptr: MutPtr<i32> = MutPtr::from_usize(body_base + 8);
        ret_ptr.write_at_offset(0, 0i32).ok_or(Errno::EFAULT)?;

        // task_info_outCnt
        let cnt_ptr: MutPtr<i32> = MutPtr::from_usize(body_base + 12);
        cnt_ptr.write_at_offset(0, out_count).ok_or(Errno::EFAULT)?;

        Ok(body_base + 16) // data area offset
    }

    /// Reply for TASK_DYLD_INFO (flavor 17).
    ///
    /// Returns 3 x u64 = 24 bytes = 6 i32-words:
    /// - all_image_info_addr: u64 (0 — not tracked by the shim)
    /// - all_image_info_size: u64 (0)
    /// - all_image_info_format: u64 (2 = 64-bit)
    fn mig_task_info_dyld(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // task_dyld_info: 3 x u64 = 24 bytes = 6 i32-words
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 24, 6)?;

        let data_ptr: MutPtr<u64> = MutPtr::from_usize(data_offset);

        // Return synthetic values.  The shim doesn't track
        // dyld_all_image_info, so return addr=0, size=0.  Callers
        // (like ICU/locale init in sort) that query TASK_DYLD_INFO
        // handle addr=0 gracefully — they just skip the dyld info path.
        data_ptr.write_at_offset(0, 0u64).ok_or(Errno::EFAULT)?; // all_image_info_addr
        data_ptr.write_at_offset(1, 0u64).ok_or(Errno::EFAULT)?; // all_image_info_size
        data_ptr.write_at_offset(2, 2u64).ok_or(Errno::EFAULT)?; // TASK_DYLD_ALL_IMAGE_INFO_64

        log_unsupported!("mig_task_info_dyld: returned addr=0, size=0, format=64-bit");

        Ok(MACH_MSG_SUCCESS)
    }

    /// Reply for MACH_TASK_BASIC_INFO (flavor 20).
    ///
    /// Returns synthetic task info: 12 i32-words = 48 bytes.
    fn mig_task_info_basic(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // mach_task_basic_info: 48 bytes = 12 i32-words
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 48, 12)?;

        // Zero-fill the data area (synthetic values).
        let data_ptr: MutPtr<u8> = MutPtr::from_usize(data_offset);
        let zeros = [0u8; 48];
        data_ptr.copy_from_slice(0, &zeros).ok_or(Errno::EFAULT)?;

        // Set plausible virtual_size and resident_size (first two u64 fields).
        let data_u64: MutPtr<u64> = MutPtr::from_usize(data_offset);
        data_u64.write_at_offset(0, 0x1_0000_0000u64).ok_or(Errno::EFAULT)?; // virtual_size
        data_u64.write_at_offset(1, 0x800_0000u64).ok_or(Errno::EFAULT)?; // resident_size

        log_unsupported!("mig_task_info_basic: returned synthetic values");

        Ok(MACH_MSG_SUCCESS)
    }

    /// Reply for TASK_FLAGS_INFO (flavor 22).
    ///
    /// Returns 1 i32-word = 4 bytes (flags = 0).
    fn mig_task_info_flags(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 4, 1)?;

        let flags_ptr: MutPtr<i32> = MutPtr::from_usize(data_offset);
        flags_ptr.write_at_offset(0, 0i32).ok_or(Errno::EFAULT)?; // no flags set

        log_unsupported!("mig_task_info_flags: returned flags=0");

        Ok(MACH_MSG_SUCCESS)
    }

    /// Reply for TASK_BASIC_INFO_32 (flavor 0/4).
    ///
    /// Returns `task_basic_info_32` = 7 i32-words = 28 bytes:
    /// - suspend_count: i32
    /// - virtual_size: u32
    /// - resident_size: u32
    /// - user_time: time_value_t (2 x i32)
    /// - system_time: time_value_t (2 x i32)
    /// - policy: i32
    fn mig_task_info_basic_32(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // task_basic_info_32: 28 bytes = 7 i32-words
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 28, 7)?;

        let data_ptr: MutPtr<u32> = MutPtr::from_usize(data_offset);

        // suspend_count = 0
        data_ptr.write_at_offset(0, 0u32).ok_or(Errno::EFAULT)?;
        // virtual_size (synthetic ~4 GiB)
        data_ptr.write_at_offset(1, 0x1000_0000u32).ok_or(Errno::EFAULT)?;
        // resident_size (synthetic ~128 MiB)
        data_ptr.write_at_offset(2, 0x0800_0000u32).ok_or(Errno::EFAULT)?;
        // user_time = {0, 0}
        data_ptr.write_at_offset(3, 0u32).ok_or(Errno::EFAULT)?;
        data_ptr.write_at_offset(4, 0u32).ok_or(Errno::EFAULT)?;
        // system_time = {0, 0}
        data_ptr.write_at_offset(5, 0u32).ok_or(Errno::EFAULT)?;
        data_ptr.write_at_offset(6, 0u32).ok_or(Errno::EFAULT)?;

        log_unsupported!("mig_task_info_basic_32: returned synthetic values");

        Ok(MACH_MSG_SUCCESS)
    }

    /// Write a minimal error reply for unsupported task_info flavors.
    fn mig_task_info_error_reply(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
        kern_return: i32,
    ) -> Result<usize, Errno> {
        // Minimal reply: Header(24) + NDR(8) + RetCode(4) = 36 bytes
        #[allow(clippy::cast_possible_truncation)]
        let reply_size: u32 = (HEADER_SIZE + 8 + 4) as u32;

        let reply_hdr = MachMsgHeader {
            msgh_bits: 0x12,
            msgh_size: reply_size,
            msgh_remote_port: hdr.msgh_local_port,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: hdr.msgh_id + MIG_REPLY_OFFSET,
        };
        let hdr_ptr: MutPtr<MachMsgHeader> = MutPtr::from_usize(msg_addr);
        hdr_ptr.write_at_offset(0, reply_hdr).ok_or(Errno::EFAULT)?;

        let body_base = msg_addr + HEADER_SIZE;

        let ndr_ptr: MutPtr<[u8; 8]> = MutPtr::from_usize(body_base);
        ndr_ptr.write_at_offset(0, NDR_RECORD).ok_or(Errno::EFAULT)?;

        let ret_ptr: MutPtr<i32> = MutPtr::from_usize(body_base + 8);
        ret_ptr.write_at_offset(0, kern_return).ok_or(Errno::EFAULT)?;

        Ok(MACH_MSG_SUCCESS)
    }
}
