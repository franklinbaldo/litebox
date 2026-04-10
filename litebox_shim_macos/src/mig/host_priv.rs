// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MIG host_priv subsystem emulation (subsystem base 400).
//!
//! Handles MIG requests sent to the HOST_SELF port (0x0503) for
//! host-level operations like `host_get_special_port`.

use core::sync::atomic::Ordering;

use crate::mig::{
    MachMsgBody, MachMsgHeader, MachMsgPortDescriptor, BODY_SIZE, HEADER_SIZE, MACH_MSG_SUCCESS,
    MACH_SEND_INVALID_DEST, PORT_DESC_SIZE, REPLY_BITS_COMPLEX,
};
use crate::{ConstPtr, MutPtr, ShimFS, Task};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::errno::Errno;

/// MIG reply ID offset: reply_id = request_id + 100.
const MIG_REPLY_OFFSET: i32 = 100;

impl<FS: ShimFS> Task<FS> {
    /// Dispatch a host_priv subsystem MIG request.
    ///
    /// Routes by `msgh_id` within the 400..499 range.
    pub(crate) fn mig_host_priv(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        match hdr.msgh_id {
            412 => self.mig_host_get_special_port(msg_addr, hdr),
            _ => {
                log_unsupported!(
                    "mig_host_priv: unhandled msgh_id={}, returning MACH_SEND_INVALID_DEST",
                    hdr.msgh_id,
                );
                Ok(MACH_SEND_INVALID_DEST)
            }
        }
    }

    /// Handle `host_get_special_port` (msgh_id=412).
    ///
    /// Request body (after 24-byte header):
    /// - NDR record (8 bytes)
    /// - node: i32 (-1 = HOST_LOCAL_NODE)
    /// - which: i32 (1 = HOST_PORT, 2 = HOST_PRIV_PORT, etc.)
    ///
    /// Reply (36 bytes total, complex):
    /// - Header (24): bits=REPLY_BITS_COMPLEX, size=36,
    ///   remote=request.msgh_local_port, local=0, voucher=0, id=512
    /// - Body (4): descriptor_count=1
    /// - Port descriptor (8): name=<port>, disposition=MOVE_SEND (17)
    fn mig_host_get_special_port(
        &self,
        msg_addr: usize,
        hdr: &MachMsgHeader,
    ) -> Result<usize, Errno> {
        // Read the request body: NDR (8 bytes) + node (4) + which (4) = 16 bytes
        // starting at msg_addr + HEADER_SIZE.
        let body_addr = msg_addr + HEADER_SIZE;
        let which_ptr: ConstPtr<i32> = ConstPtr::from_usize(body_addr + 8 + 4);
        let which: i32 = which_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

        log_unsupported!(
            "mig_host_get_special_port: which={which}, reply_port={:#x}",
            hdr.msgh_local_port,
        );

        // Map `which` to a port name.
        let port = match which {
            // HOST_PORT (1) -> HOST_SELF
            1 => 0x0503u32,
            // HOST_PRIV_PORT (2) -> HOST_SELF (we are the only task)
            2 => 0x0503u32,
            // Unknown -- allocate a synthetic port.
            _ => self
                .process
                .next_mach_port
                .fetch_add(0x100, Ordering::Relaxed),
        };

        // Write the reply in-place at msg_addr.
        // Total reply size: HEADER(24) + BODY(4) + PORT_DESC(8) = 36 bytes.
        let reply_size: u32 = (HEADER_SIZE + BODY_SIZE + PORT_DESC_SIZE) as u32;

        // Write reply header.
        let reply_hdr = MachMsgHeader {
            msgh_bits: REPLY_BITS_COMPLEX,
            msgh_size: reply_size,
            msgh_remote_port: hdr.msgh_local_port,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: hdr.msgh_id + MIG_REPLY_OFFSET, // 512
        };
        let hdr_ptr: MutPtr<MachMsgHeader> = MutPtr::from_usize(msg_addr);
        hdr_ptr.write_at_offset(0, reply_hdr).ok_or(Errno::EFAULT)?;

        // Write reply body (descriptor count = 1).
        let body = MachMsgBody {
            msgh_descriptor_count: 1,
        };
        let body_ptr: MutPtr<MachMsgBody> = MutPtr::from_usize(msg_addr + HEADER_SIZE);
        body_ptr.write_at_offset(0, body).ok_or(Errno::EFAULT)?;

        // Write port descriptor (MACH_MSG_TYPE_MOVE_SEND = 17).
        let desc = MachMsgPortDescriptor::new(port, 17);
        let desc_ptr: MutPtr<MachMsgPortDescriptor> =
            MutPtr::from_usize(msg_addr + HEADER_SIZE + BODY_SIZE);
        desc_ptr.write_at_offset(0, desc).ok_or(Errno::EFAULT)?;

        log_unsupported!("mig_host_get_special_port: replied with port={port:#x}, reply_id=512");

        Ok(MACH_MSG_SUCCESS)
    }
}
