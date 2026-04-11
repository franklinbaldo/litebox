// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MIG task subsystem emulation (subsystem base 3400).
//!
//! Handles MIG requests sent to the TASK_SELF port (0x0103) for
//! task-level operations like `task_info`, `semaphore_create`, and
//! `semaphore_destroy`.
//!
//! # Correct MIG IDs (from XNU `task.defs`)
//!
//! | Routine             | Request | Reply |
//! |---------------------|---------|-------|
//! | `task_info`         |  3405   | 3505  |
//! | `semaphore_create`  |  3418   | 3518  |
//! | `semaphore_destroy` |  3419   | 3519  |

use core::sync::atomic::Ordering;

use crate::mig::{
    MachMsgBody, MachMsgHeader, MachMsgPortDescriptor, BODY_SIZE, HEADER_SIZE, MACH_MSG_SUCCESS,
    MACH_SEND_INVALID_DEST, NDR_RECORD, PORT_DESC_SIZE, REPLY_BITS_COMPLEX,
};
use crate::{ConstPtr, MutPtr, ShimFS, Task};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

/// MIG reply ID offset: reply_id = request_id + 100.
const MIG_REPLY_OFFSET: i32 = 100;

// -- task_info flavors --------------------------------------------------

/// `TASK_BASIC_INFO_32` (4) — legacy 32-bit basic task info.
const TASK_BASIC_INFO_32: i32 = 4;

/// `TASK_DYLD_INFO` (17) — dyld all-image-info address.
const TASK_DYLD_INFO: i32 = 17;

/// `TASK_BASIC_INFO_64` / `TASK_BASIC_INFO` (18) — 64-bit basic task
/// info.  On arm64e, `TASK_BASIC_INFO` resolves to this flavor.
const TASK_BASIC_INFO_64: i32 = 18;

/// `MACH_TASK_BASIC_INFO` (20) — basic task info (newer API).
const MACH_TASK_BASIC_INFO: i32 = 20;

/// `TASK_FLAGS_INFO` (22) — task flags.
const TASK_FLAGS_INFO: i32 = 22;

/// `TASK_FLAGS_INFO` (28) — actual value on macOS 15+.
const TASK_FLAGS_INFO_28: i32 = 28;

// -- MIG msgh_id constants (from XNU task.defs) -------------------------

/// `task_info` — query task-level statistics (routine 5).
const MSGH_ID_TASK_INFO: i32 = 3405;

/// `semaphore_create` — create a Mach semaphore (routine 18).
const MSGH_ID_SEMAPHORE_CREATE: i32 = 3418;

/// `semaphore_destroy` — destroy a Mach semaphore (routine 19).
const MSGH_ID_SEMAPHORE_DESTROY: i32 = 3419;

impl<FS: ShimFS> Task<FS> {
    /// Dispatch a task subsystem MIG request.
    ///
    /// Routes by `msgh_id` within the 3400..3499 range.
    pub(crate) fn mig_task(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        match hdr.msgh_id {
            MSGH_ID_TASK_INFO => self.mig_task_info(msg_addr, hdr),
            MSGH_ID_SEMAPHORE_CREATE => self.mig_semaphore_create(msg_addr, hdr),
            MSGH_ID_SEMAPHORE_DESTROY => self.mig_semaphore_destroy(msg_addr, hdr),
            _ => {
                log_unsupported!(
                    "mig_task: unhandled msgh_id={}, returning MACH_SEND_INVALID_DEST",
                    hdr.msgh_id,
                );
                Ok(MACH_SEND_INVALID_DEST)
            }
        }
    }

    // -- semaphore_create (msgh_id=3418) --------------------------------

    /// Handle `semaphore_create` (msgh_id=3418).
    ///
    /// Request body (after 24-byte header):
    /// - NDR record (8 bytes) at offset 24
    /// - policy: i32 at offset 32
    /// - value: i32 at offset 36
    ///
    /// Reply (40 bytes, complex — returns a 12-byte port descriptor):
    /// - Header (24): bits=REPLY_BITS_COMPLEX, size=40,
    ///   remote_port=0, local=0, voucher=0, id=3518
    /// - Body (4): descriptor_count=1
    /// - Port descriptor (12): name=new_port, pad1=0,
    ///   disposition=MOVE_SEND(17), type=PORT(0)
    fn mig_semaphore_create(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // Parse request: NDR(8) + policy(4) + value(4) starting at offset 24.
        let value_ptr: ConstPtr<i32> = ConstPtr::from_usize(msg_addr + HEADER_SIZE + 8 + 4);
        let initial_value: i32 = value_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

        // Allocate a new Mach port name for the semaphore.
        let port = self
            .process
            .next_mach_port
            .fetch_add(0x100, Ordering::Relaxed);

        // Register the semaphore in the manager with the initial count.
        self.global
            .semaphore_manager
            .create(port, initial_value);

        log_unsupported!(
            "mig_semaphore_create: created port={port:#x}, initial_value={initial_value}"
        );

        // Write complex reply: Header(24) + Body(4) + PortDesc(12) = 40 bytes.
        #[allow(clippy::cast_possible_truncation)]
        let reply_size: u32 = (HEADER_SIZE + BODY_SIZE + PORT_DESC_SIZE) as u32;

        let reply_hdr = MachMsgHeader {
            msgh_bits: REPLY_BITS_COMPLEX,
            msgh_size: reply_size,
            msgh_remote_port: 0,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: hdr.msgh_id + MIG_REPLY_OFFSET, // 3518
        };
        let hdr_ptr: MutPtr<MachMsgHeader> = MutPtr::from_usize(msg_addr);
        hdr_ptr.write_at_offset(0, reply_hdr).ok_or(Errno::EFAULT)?;

        // Body: descriptor_count = 1
        let body = MachMsgBody {
            msgh_descriptor_count: 1,
        };
        let body_ptr: MutPtr<MachMsgBody> = MutPtr::from_usize(msg_addr + HEADER_SIZE);
        body_ptr.write_at_offset(0, body).ok_or(Errno::EFAULT)?;

        // Port descriptor (12 bytes): MACH_MSG_TYPE_MOVE_SEND = 17
        let desc = MachMsgPortDescriptor::new(port, 17);
        let desc_ptr: MutPtr<MachMsgPortDescriptor> =
            MutPtr::from_usize(msg_addr + HEADER_SIZE + BODY_SIZE);
        desc_ptr.write_at_offset(0, desc).ok_or(Errno::EFAULT)?;

        Ok(MACH_MSG_SUCCESS)
    }

    // -- semaphore_destroy (msgh_id=3419) -------------------------------

    /// Handle `semaphore_destroy` (msgh_id=3419).
    ///
    /// Request body (after 24-byte header, complex message):
    /// - Body (4): descriptor_count=1
    /// - Port descriptor (12): the semaphore port to destroy
    ///
    /// Reply (non-complex, 36 bytes):
    /// - Header (24): bits=0x12, size=36, remote_port=0, local=0,
    ///   voucher=0, id=3519
    /// - NDR record (8 bytes)
    /// - RetCode: i32 = KERN_SUCCESS (0)
    fn mig_semaphore_destroy(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // The request is a complex message: Header(24) + Body(4) + PortDesc(12).
        // Read the port name from the descriptor.
        let name_ptr: ConstPtr<u32> =
            ConstPtr::from_usize(msg_addr + HEADER_SIZE + BODY_SIZE);
        let port: u32 = name_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

        let existed = self.global.semaphore_manager.destroy(port);

        log_unsupported!(
            "mig_semaphore_destroy: port={port:#x}, existed={existed}"
        );

        // Write non-complex reply: Header(24) + NDR(8) + RetCode(4) = 36 bytes.
        #[allow(clippy::cast_possible_truncation)]
        let reply_size: u32 = (HEADER_SIZE + 8 + 4) as u32;

        let reply_hdr = MachMsgHeader {
            msgh_bits: 0x12, // MACH_MSG_TYPE_MOVE_SEND_ONCE
            msgh_size: reply_size,
            msgh_remote_port: 0,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: hdr.msgh_id + MIG_REPLY_OFFSET, // 3519
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

        Ok(MACH_MSG_SUCCESS)
    }

    // -- task_info (msgh_id=3405) ---------------------------------------

    /// Handle `task_info` (msgh_id=3405).
    ///
    /// Request body (after 24-byte header):
    /// - NDR record (8 bytes) at offset 24
    /// - flavor: i32 at offset 32
    /// - task_info_outCnt: i32 at offset 36
    ///
    /// Reply (non-complex, variable size):
    /// - Header (24): bits=0x12, size=40+outCnt*4, remote_port=0,
    ///   local=0, voucher=0, id=3505
    /// - NDR record (8 bytes)
    /// - RetCode: i32 = 0 (KERN_SUCCESS)
    /// - task_info_outCnt: i32 = count of i32 words returned
    /// - task_info_out: variable-length data (outCnt * 4 bytes)
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
            TASK_BASIC_INFO_32 => self.mig_task_info_basic_32(msg_addr, hdr),
            TASK_DYLD_INFO => self.mig_task_info_dyld(msg_addr, hdr),
            TASK_BASIC_INFO_64 => self.mig_task_info_basic_64(msg_addr, hdr),
            MACH_TASK_BASIC_INFO => self.mig_task_info_basic(msg_addr, hdr),
            TASK_FLAGS_INFO | TASK_FLAGS_INFO_28 => {
                self.mig_task_info_flags(msg_addr, hdr)
            }
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
    /// Returns the byte offset of the start of the data area
    /// (body_base + 16, i.e. past NDR + RetCode + outCnt).
    fn write_task_info_reply_header(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
        data_size: usize,
        out_count: i32,
    ) -> Result<usize, Errno> {
        // Reply: Header(24) + NDR(8) + RetCode(4) + outCnt(4) + data
        // Total = 40 + data_size
        #[allow(clippy::cast_possible_truncation)]
        let reply_size: u32 = (HEADER_SIZE + 8 + 4 + 4 + data_size) as u32;

        let reply_hdr = MachMsgHeader {
            msgh_bits: 0x12, // MACH_MSG_TYPE_MOVE_SEND_ONCE
            msgh_size: reply_size,
            msgh_remote_port: 0,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: hdr.msgh_id + MIG_REPLY_OFFSET, // 3505
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

    /// Reply for `TASK_DYLD_INFO` (flavor 17).
    ///
    /// Returns 3 × u64 = 24 bytes = 6 i32-words:
    /// - `all_image_info_addr`: u64 (0 — not tracked by the shim)
    /// - `all_image_info_size`: u64 (0)
    /// - `all_image_info_format`: u64 (2 = 64-bit)
    fn mig_task_info_dyld(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // task_dyld_info: 3 × u64 = 24 bytes = 6 i32-words
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 24, 6)?;

        let data_ptr: MutPtr<u64> = MutPtr::from_usize(data_offset);

        data_ptr.write_at_offset(0, 0u64).ok_or(Errno::EFAULT)?; // all_image_info_addr
        data_ptr.write_at_offset(1, 0u64).ok_or(Errno::EFAULT)?; // all_image_info_size
        data_ptr.write_at_offset(2, 2u64).ok_or(Errno::EFAULT)?; // TASK_DYLD_ALL_IMAGE_INFO_64

        log_unsupported!("mig_task_info_dyld: returned addr=0, size=0, format=64-bit");

        Ok(MACH_MSG_SUCCESS)
    }

    /// Reply for `MACH_TASK_BASIC_INFO` (flavor 20).
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

    /// Reply for `TASK_FLAGS_INFO` (flavor 22 or 28).
    ///
    /// Returns 1 i32-word = 4 bytes (flags = 0).
    fn mig_task_info_flags(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 4, 1)?;

        let flags_ptr: MutPtr<i32> = MutPtr::from_usize(data_offset);
        flags_ptr.write_at_offset(0, 0i32).ok_or(Errno::EFAULT)?;

        log_unsupported!("mig_task_info_flags: returned flags=0");

        Ok(MACH_MSG_SUCCESS)
    }

    /// Reply for `TASK_BASIC_INFO_64` (flavor 18, the default on arm64e).
    ///
    /// Returns `task_basic_info_64_data_t` = 10 i32-words = 40 bytes:
    ///
    /// ```text
    /// offset  0: suspend_count  (i32)
    /// offset  4: virtual_size   (u32, lower 32 bits of mach_vm_size_t)
    /// offset  8: virtual_size   (u32, upper 32 bits)
    /// offset 12: resident_size  (u32, lower 32 bits)
    /// offset 16: resident_size  (u32, upper 32 bits)
    /// offset 20: user_time.sec  (i32)
    /// offset 24: user_time.usec (i32)
    /// offset 28: system_time.sec  (i32)
    /// offset 32: system_time.usec (i32)
    /// offset 36: policy         (i32)
    /// ```
    fn mig_task_info_basic_64(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // task_basic_info_64: 40 bytes = 10 i32-words
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 40, 10)?;

        // Zero-fill first, then set specific fields.
        let data_ptr: MutPtr<u8> = MutPtr::from_usize(data_offset);
        let zeros = [0u8; 40];
        data_ptr.copy_from_slice(0, &zeros).ok_or(Errno::EFAULT)?;

        let i32_ptr: MutPtr<i32> = MutPtr::from_usize(data_offset);

        // suspend_count = 0 (already zeroed)

        // virtual_size (u64 at offset 4, split across i32 words 1 and 2).
        // Use a plausible value: ~4 GiB = 0x1_0000_0000.
        let vsize: u64 = 0x1_0000_0000;
        #[allow(clippy::cast_possible_truncation)]
        let vsize_lo = vsize as i32;
        let vsize_hi = (vsize >> 32) as i32;
        i32_ptr.write_at_offset(1, vsize_lo).ok_or(Errno::EFAULT)?;
        i32_ptr.write_at_offset(2, vsize_hi).ok_or(Errno::EFAULT)?;

        // resident_size (u64 at offset 12, split across i32 words 3 and 4).
        let rsize: u64 = 0x800_0000; // ~128 MiB
        #[allow(clippy::cast_possible_truncation)]
        let rsize_lo = rsize as i32;
        let rsize_hi = (rsize >> 32) as i32;
        i32_ptr.write_at_offset(3, rsize_lo).ok_or(Errno::EFAULT)?;
        i32_ptr.write_at_offset(4, rsize_hi).ok_or(Errno::EFAULT)?;

        // user_time, system_time, policy all zeroed.
        // policy = POLICY_TIMESHARE = 1
        i32_ptr.write_at_offset(9, 1i32).ok_or(Errno::EFAULT)?;

        log_unsupported!("mig_task_info_basic_64: returned synthetic values");

        Ok(MACH_MSG_SUCCESS)
    }

    /// Reply for `TASK_BASIC_INFO_32` (flavor 4).
    ///
    /// Returns `task_basic_info_32_data_t` = 8 i32-words = 32 bytes:
    ///
    /// ```text
    /// offset  0: suspend_count  (i32)
    /// offset  4: virtual_size   (u32, 32-bit truncated)
    /// offset  8: resident_size  (u32, 32-bit truncated)
    /// offset 12: user_time.sec  (i32)
    /// offset 16: user_time.usec (i32)
    /// offset 20: system_time.sec  (i32)
    /// offset 24: system_time.usec (i32)
    /// offset 28: policy         (i32)
    /// ```
    fn mig_task_info_basic_32(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // task_basic_info_32: 32 bytes = 8 i32-words
        let data_offset = self.write_task_info_reply_header(msg_addr, hdr, 32, 8)?;

        let data_ptr: MutPtr<u32> = MutPtr::from_usize(data_offset);

        // suspend_count = 0
        data_ptr.write_at_offset(0, 0u32).ok_or(Errno::EFAULT)?;
        // virtual_size (truncated to 32 bits, ~256 MiB)
        data_ptr.write_at_offset(1, 0x1000_0000u32).ok_or(Errno::EFAULT)?;
        // resident_size (~128 MiB)
        data_ptr.write_at_offset(2, 0x0800_0000u32).ok_or(Errno::EFAULT)?;
        // user_time = {0, 0}
        data_ptr.write_at_offset(3, 0u32).ok_or(Errno::EFAULT)?;
        data_ptr.write_at_offset(4, 0u32).ok_or(Errno::EFAULT)?;
        // system_time = {0, 0}
        data_ptr.write_at_offset(5, 0u32).ok_or(Errno::EFAULT)?;
        data_ptr.write_at_offset(6, 0u32).ok_or(Errno::EFAULT)?;
        // policy = POLICY_TIMESHARE = 1
        data_ptr.write_at_offset(7, 1u32).ok_or(Errno::EFAULT)?;

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
            msgh_remote_port: 0,
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
