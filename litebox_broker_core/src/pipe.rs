// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned byte pipe operations.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::pipe::{MAX_PIPE_TRANSFER_SIZE, PipeEndpoint, PipeReadinessState};
use spin::rwlock::RwLock;

use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result};

/// Maximum capacity accepted by the control-path pipe prototype.
pub const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

/// Creates a broker-owned pipe and returns its read and write endpoint handles.
///
/// # Panics
///
/// Panics if rollback of a newly-created read endpoint unexpectedly fails
/// after write-endpoint creation fails.
pub fn create(
    session: &BrokerSession,
    capacity: u64,
    atomic_write_size: u64,
) -> Result<(ObjectHandle, ObjectHandle)> {
    let capacity = usize::try_from(capacity).map_err(|_| BrokerError::ResourceExhausted)?;
    let atomic_write_size =
        usize::try_from(atomic_write_size).map_err(|_| BrokerError::ResourceExhausted)?;
    if capacity == 0
        || capacity > MAX_PIPE_CAPACITY
        || atomic_write_size > capacity
        || atomic_write_size > MAX_PIPE_TRANSFER_SIZE as usize
    {
        return Err(BrokerError::ResourceExhausted);
    }

    let mut data = VecDeque::new();
    data.try_reserve_exact(capacity)
        .map_err(|_| BrokerError::ResourceExhausted)?;
    let state = Arc::new(RwLock::new(PipeState {
        data,
        capacity,
        atomic_write_size,
        read_open: true,
        write_open: true,
    }));

    let read_handle = session.create_object_reference(ObjectEntry::PipeReader(PipeReadEnd {
        state: Arc::clone(&state),
    }))?;
    let write_handle =
        match session.create_object_reference(ObjectEntry::PipeWriter(PipeWriteEnd { state })) {
            Ok(handle) => handle,
            Err(error) => {
                session
                    .close_object_reference(read_handle)
                    .expect("newly created pipe read handle must be valid");
                return Err(error);
            }
        };

    Ok((read_handle, write_handle))
}

/// Reads up to `length` bytes from a broker-owned pipe.
pub fn read(session: &BrokerSession, handle: ObjectHandle, length: u32) -> Result<Vec<u8>> {
    if length > MAX_PIPE_TRANSFER_SIZE {
        return Err(BrokerError::ResourceExhausted);
    }
    session.with_authorized_object(handle, ObjectRights::WAIT, |object| match object {
        ObjectEntry::PipeReader(end) => end.read(length as usize),
        ObjectEntry::Event(_) | ObjectEntry::PipeWriter(_) => Err(BrokerError::InvalidRights),
    })
}

/// Writes bytes to a broker-owned pipe.
pub fn write(session: &BrokerSession, handle: ObjectHandle, data: &[u8]) -> Result<usize> {
    if data.len() > MAX_PIPE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    session.with_authorized_object(handle, ObjectRights::WRITE, |object| match object {
        ObjectEntry::PipeWriter(end) => end.write(data),
        ObjectEntry::Event(_) | ObjectEntry::PipeReader(_) => Err(BrokerError::InvalidRights),
    })
}

/// Returns the current readiness of one pipe endpoint.
pub fn check_readiness(
    session: &BrokerSession,
    handle: ObjectHandle,
) -> Result<PipeReadinessState> {
    session.with_authorized_object(handle, ObjectRights::WAIT, |object| match object {
        ObjectEntry::PipeReader(end) => Ok(end.readiness()),
        ObjectEntry::PipeWriter(end) => Ok(end.readiness()),
        ObjectEntry::Event(_) => Err(BrokerError::InvalidRights),
    })
}

pub(crate) struct PipeReadEnd {
    state: Arc<RwLock<PipeState>>,
}

impl PipeReadEnd {
    fn read(&self, length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut state = self.state.write();
        if state.data.is_empty() {
            return if state.write_open {
                Err(BrokerError::WouldBlock)
            } else {
                Ok(Vec::new())
            };
        }

        let read_len = length.min(state.data.len());
        let mut data = Vec::new();
        data.try_reserve_exact(read_len)
            .map_err(|_| BrokerError::ResourceExhausted)?;
        data.extend(state.data.drain(..read_len));
        Ok(data)
    }

    fn readiness(&self) -> PipeReadinessState {
        let state = self.state.read();
        PipeReadinessState {
            endpoint: PipeEndpoint::Read,
            ready: !state.data.is_empty(),
            peer_closed: !state.write_open,
        }
    }
}

impl Drop for PipeReadEnd {
    fn drop(&mut self) {
        self.state.write().read_open = false;
    }
}

pub(crate) struct PipeWriteEnd {
    state: Arc<RwLock<PipeState>>,
}

impl PipeWriteEnd {
    fn write(&self, data: &[u8]) -> Result<usize> {
        let mut state = self.state.write();
        if !state.read_open {
            return Err(BrokerError::PeerClosed);
        }
        if data.is_empty() {
            return Ok(0);
        }

        let available = state.capacity - state.data.len();
        if available == 0 || (data.len() <= state.atomic_write_size && available < data.len()) {
            return Err(BrokerError::WouldBlock);
        }

        let write_len = available.min(data.len());
        state.data.extend(&data[..write_len]);
        Ok(write_len)
    }

    fn readiness(&self) -> PipeReadinessState {
        let state = self.state.read();
        PipeReadinessState {
            endpoint: PipeEndpoint::Write,
            ready: state.read_open && state.data.len() < state.capacity,
            peer_closed: !state.read_open,
        }
    }
}

impl Drop for PipeWriteEnd {
    fn drop(&mut self) {
        self.state.write().write_open = false;
    }
}

struct PipeState {
    data: VecDeque<u8>,
    capacity: usize,
    atomic_write_size: usize,
    read_open: bool,
    write_open: bool,
}
