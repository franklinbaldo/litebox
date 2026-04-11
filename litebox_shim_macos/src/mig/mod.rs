// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MIG (Mach Interface Generator) message emulation.
//!
//! Provides wire format structs for Mach IPC messages and a dispatcher
//! that routes incoming MIG requests by `msgh_id` to per-subsystem
//! handlers.

pub(crate) mod host_priv;
pub(crate) mod task;

use litebox::platform::RawConstPointer as _;
use litebox_common_macos::errno::Errno;
use zerocopy::{FromBytes, IntoBytes};

use crate::{ConstPtr, ShimFS, Task};

// -- Wire format structs -----------------------------------------------

/// Mach message header (`mach_msg_header_t`), 24 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[allow(clippy::struct_field_names)]
pub(crate) struct MachMsgHeader {
    pub msgh_bits: u32,
    pub msgh_size: u32,
    pub msgh_remote_port: u32,
    pub msgh_local_port: u32,
    pub msgh_voucher_port: u32,
    pub msgh_id: i32,
}

/// Mach message body (`mach_msg_body_t`), 4 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
pub(crate) struct MachMsgBody {
    pub msgh_descriptor_count: u32,
}

/// Mach port descriptor (`mach_msg_port_descriptor_t`), 8 bytes.
///
/// Layout: name (u32) + packed disposition/type (u32).
/// Disposition is in bits 16..23, type (0 = port) in bits 24..31.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
pub(crate) struct MachMsgPortDescriptor {
    pub name: u32,
    /// Bits 16..23 = disposition, bits 24..31 = descriptor type (0 = port).
    pub disposition_type: u32,
}

impl MachMsgPortDescriptor {
    /// Create a port descriptor with the given name and disposition.
    ///
    /// Type is always 0 (MACH_MSG_PORT_DESCRIPTOR).
    pub fn new(name: u32, disposition: u8) -> Self {
        Self {
            name,
            disposition_type: u32::from(disposition) << 0x10,
        }
    }
}

/// NDR record constant (Network Data Representation).
///
/// Little-endian, 2-byte integers, ASCII characters, IEEE 754 floats.
#[allow(dead_code)] // Used by future MIG subsystem handlers
pub(crate) const NDR_RECORD: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];

// -- Mach message option flags -----------------------------------------

/// MACH_SEND_MSG -- message contains a send operation.
const MACH_SEND_MSG: usize = 0x0000_0001;

// -- Mach message result codes -----------------------------------------

/// MACH_MSG_SUCCESS
pub(crate) const MACH_MSG_SUCCESS: usize = 0;

/// MACH_SEND_INVALID_DEST
pub(crate) const MACH_SEND_INVALID_DEST: usize = 0x1000_0003;

// -- Reply header helpers ----------------------------------------------

/// MACH_MSGH_BITS_COMPLEX -- set when message contains descriptors.
pub(crate) const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;

/// Construct msgh_bits for a complex reply with MOVE_SEND_ONCE remote.
///
/// Remote bits = 18 (MACH_MSG_TYPE_MOVE_SEND_ONCE) in bits 0..7.
pub(crate) const REPLY_BITS_COMPLEX: u32 = MACH_MSGH_BITS_COMPLEX | 0x12;

// -- Sizes -------------------------------------------------------------

/// Size of MachMsgHeader in bytes.
pub(crate) const HEADER_SIZE: usize = core::mem::size_of::<MachMsgHeader>();

/// Size of MachMsgBody in bytes.
pub(crate) const BODY_SIZE: usize = core::mem::size_of::<MachMsgBody>();

/// Size of MachMsgPortDescriptor in bytes.
pub(crate) const PORT_DESC_SIZE: usize = core::mem::size_of::<MachMsgPortDescriptor>();

// -- Dispatcher --------------------------------------------------------

impl<FS: ShimFS> Task<FS> {
    /// Dispatch a MIG message.
    ///
    /// Reads the Mach message header from `msg_addr` in guest memory,
    /// routes by `msgh_id` to the appropriate subsystem handler, and
    /// writes the reply back to the same address if the caller requested
    /// both send and receive.
    ///
    /// # Arguments
    /// - `msg_addr`: guest address of the message buffer
    /// - `options`: mach_msg options (SEND/RCV flags)
    pub(crate) fn dispatch_mig(&self, msg_addr: usize, options: usize) -> Result<usize, Errno> {
        // Only process if this is a send operation.
        if options & MACH_SEND_MSG == 0 {
            log_unsupported!(
                "dispatch_mig: no MACH_SEND_MSG in options {options:#x}, returning MACH_MSG_SUCCESS"
            );
            return Ok(MACH_MSG_SUCCESS);
        }

        // Read the message header from guest memory.
        let hdr_ptr: ConstPtr<MachMsgHeader> = ConstPtr::from_usize(msg_addr);
        let hdr: MachMsgHeader = hdr_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

        log_unsupported!(
            "dispatch_mig: msgh_id={}, remote={:#x}, local={:#x}, bits={:#x}, size={}",
            hdr.msgh_id,
            hdr.msgh_remote_port,
            hdr.msgh_local_port,
            hdr.msgh_bits,
            hdr.msgh_size,
        );

        // Route by msgh_id to subsystem handlers.
        if (400..500).contains(&hdr.msgh_id) {
            // host_priv subsystem: base 400..499
            self.mig_host_priv(msg_addr, &hdr)
        } else if (3400..3500).contains(&hdr.msgh_id) {
            // task subsystem: base 3400..3499
            self.mig_task(msg_addr, &hdr)
        } else {
            // Unknown MIG subsystem -- return MACH_SEND_INVALID_DEST.
            log_unsupported!(
                "dispatch_mig: unknown msgh_id={}, returning MACH_SEND_INVALID_DEST",
                hdr.msgh_id,
            );
            Ok(MACH_SEND_INVALID_DEST)
        }
    }
}
