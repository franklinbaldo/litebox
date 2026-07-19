// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Channel-neutral broker-side protocol/core adapter.
//!
//! This crate wires `litebox_broker_core` to any implementation of the neutral
//! host-side control-channel trait. Concrete channels live in separate crates such as
//! `litebox_broker_transport`.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use litebox_broker_core::{BrokerCore, BrokerSession, CallerCredential};
use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::{
    HostControlChannel, HostNotificationChannel, HostReceive, PeerCredential,
};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{AddEventResponse, CreateEventResponse};
use litebox_broker_protocol::message::{
    BrokerHandshakeResponse, BrokerRequest, BrokerResponse, EventRequest, EventResponse,
    PipeRequest, PipeResponse,
};
use litebox_broker_protocol::pipe::{CreatePipeResponse, ReadPipeResponse, WritePipeResponse};
use litebox_broker_protocol::pipe::{
    PIPE_SHARED_MEMORY_REGION_SIZE, PIPE_SHARED_MEMORY_SIZE, ReadPipeSharedResponse,
};
use litebox_broker_protocol::shared_memory::SharedMemory;

mod error;

pub use error::{BrokerHostError, Result};

/// Authenticates, negotiates, and serves one broker association over paired
/// control and notification channels.
///
/// The deployment must bind both channels to the same authenticated peer
/// association. Active requests and responses remain on the control channel;
/// broker-initiated readiness wakeups are sent on the notification channel.
/// Event mutations caused by control requests return readiness in their control
/// response and do not also emit a duplicate notification.
pub fn serve_connection<ControlChannel, NotificationChannel, ChannelError>(
    core: &BrokerCore,
    control_channel: &mut ControlChannel,
    _notification_channel: &mut NotificationChannel,
) -> Result<ConnectionTermination, ChannelError>
where
    ControlChannel: HostControlChannel<Error = ChannelError>,
    NotificationChannel: HostNotificationChannel<Error = ChannelError>,
{
    let peer_credential = control_channel
        .peer_credential()
        .map_err(BrokerHostError::Channel)?;
    let caller_credential = match peer_credential {
        PeerCredential::Unauthenticated => CallerCredential::Unauthenticated,
        _ => return Err(BrokerHostError::Broker(ErrorCode::PolicyDenied)),
    };
    let session = core.create_session(caller_credential)?;
    let mut pipe_shared_memories = BTreeMap::new();

    loop {
        let request = match control_channel
            .recv_handshake_request()
            .map_err(BrokerHostError::Channel)?
        {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                control_channel
                    .send_handshake_response(&BrokerHandshakeResponse::Error(
                        ErrorCode::ProtocolState,
                    ))
                    .map_err(BrokerHostError::Channel)?;
                return Ok(ConnectionTermination::ProtocolViolation);
            }
            HostReceive::PeerClosed => return Ok(ConnectionTermination::PeerClosed),
        };

        let negotiated = request.protocol_version == BROKER_PROTOCOL_VERSION;
        let response = if negotiated {
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }
        } else {
            BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }
        };
        control_channel
            .send_handshake_response(&response)
            .map_err(BrokerHostError::Channel)?;
        if negotiated {
            break;
        }
    }

    loop {
        let request = match control_channel
            .recv_request()
            .map_err(BrokerHostError::Channel)?
        {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                control_channel
                    .send_response(&BrokerResponse::Error(ErrorCode::ProtocolState), None)
                    .map_err(BrokerHostError::Channel)?;
                return Ok(ConnectionTermination::ProtocolViolation);
            }
            HostReceive::PeerClosed => break,
        };

        let response = handle_request(
            &session,
            request,
            control_channel,
            &mut pipe_shared_memories,
        )
        .map_err(BrokerHostError::Channel)?;
        control_channel
            .send_response(&response.response, response.shared_memory.as_deref())
            .map_err(BrokerHostError::Channel)?;
    }

    Ok(ConnectionTermination::PeerClosed)
}

struct HandledResponse<Memory> {
    response: BrokerResponse,
    shared_memory: Option<Arc<Memory>>,
}

struct PipeSharedMemory<Memory> {
    memory: Arc<Memory>,
    endpoint: SharedPipeEndpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedPipeEndpoint {
    Read,
    Write,
}

fn handle_request<Channel: HostControlChannel>(
    session: &BrokerSession,
    request: BrokerRequest,
    channel: &mut Channel,
    pipe_shared_memories: &mut BTreeMap<ObjectHandle, PipeSharedMemory<Channel::SharedMemory>>,
) -> core::result::Result<HandledResponse<Channel::SharedMemory>, Channel::Error> {
    let mut shared_memory = None;
    match request {
        BrokerRequest::CloseObject(handle) => match session.close_object_reference(handle) {
            Ok(()) => {
                pipe_shared_memories.remove(&handle);
                Ok(HandledResponse {
                    response: BrokerResponse::ObjectClosed,
                    shared_memory,
                })
            }
            Err(error) => Ok(HandledResponse {
                response: BrokerResponse::Error(error.into()),
                shared_memory,
            }),
        },
        BrokerRequest::CheckReadiness(handle) => Ok(HandledResponse {
            response: match session.check_readiness(handle) {
                Ok(readiness) => BrokerResponse::Readiness(readiness),
                Err(error) => BrokerResponse::Error(error.into()),
            },
            shared_memory,
        }),
        BrokerRequest::Event(request) => Ok(HandledResponse {
            response: handle_event_request(session, request),
            shared_memory,
        }),
        BrokerRequest::Pipe(PipeRequest::Create(request)) => {
            let response = match litebox_broker_core::pipe::create(
                session,
                request.capacity,
                request.atomic_write_size,
            ) {
                Ok((read_handle, write_handle)) => {
                    let memory = match channel.create_shared_memory(PIPE_SHARED_MEMORY_SIZE) {
                        Ok(memory) => memory,
                        Err(error) => {
                            session
                                .close_object_reference(read_handle)
                                .expect("new pipe read handle must be valid");
                            session
                                .close_object_reference(write_handle)
                                .expect("new pipe write handle must be valid");
                            return Err(error);
                        }
                    };
                    let has_shared_memory = memory.is_some();
                    if let Some(memory) = memory {
                        if memory.len() != PIPE_SHARED_MEMORY_SIZE {
                            session
                                .close_object_reference(read_handle)
                                .expect("new pipe read handle must be valid");
                            session
                                .close_object_reference(write_handle)
                                .expect("new pipe write handle must be valid");
                            return Ok(HandledResponse {
                                response: BrokerResponse::Error(ErrorCode::Internal),
                                shared_memory: None,
                            });
                        }
                        let memory = Arc::new(memory);
                        pipe_shared_memories.insert(
                            read_handle,
                            PipeSharedMemory {
                                memory: Arc::clone(&memory),
                                endpoint: SharedPipeEndpoint::Read,
                            },
                        );
                        pipe_shared_memories.insert(
                            write_handle,
                            PipeSharedMemory {
                                memory: Arc::clone(&memory),
                                endpoint: SharedPipeEndpoint::Write,
                            },
                        );
                        shared_memory = Some(memory);
                    }
                    BrokerResponse::Pipe(PipeResponse::Create(CreatePipeResponse {
                        read_handle,
                        write_handle,
                        shared_memory: has_shared_memory,
                    }))
                }
                Err(error) => BrokerResponse::Error(error.into()),
            };
            Ok(HandledResponse {
                response,
                shared_memory,
            })
        }
        BrokerRequest::Pipe(request) => Ok(HandledResponse {
            response: handle_pipe_request(session, request, pipe_shared_memories),
            shared_memory,
        }),
    }
}

fn handle_pipe_request<Memory: SharedMemory>(
    session: &BrokerSession,
    request: PipeRequest,
    pipe_shared_memories: &BTreeMap<ObjectHandle, PipeSharedMemory<Memory>>,
) -> BrokerResponse {
    let response: core::result::Result<PipeResponse, ErrorCode> = match request {
        PipeRequest::Create(_) => unreachable!("pipe creation is handled with the control channel"),
        PipeRequest::Read(request) => {
            litebox_broker_core::pipe::read(session, request.handle, request.length)
                .map(|data| PipeResponse::Read(ReadPipeResponse { data }))
                .map_err(Into::into)
        }
        PipeRequest::ReadShared(request) => {
            let Some(shared) = pipe_shared_memories.get(&request.handle) else {
                return BrokerResponse::Error(ErrorCode::InvalidRights);
            };
            if shared.endpoint != SharedPipeEndpoint::Read {
                return BrokerResponse::Error(ErrorCode::InvalidRights);
            }
            let Some(offset) = shared_memory_offset(shared, 0, request.offset, request.length)
            else {
                return BrokerResponse::Error(ErrorCode::MalformedRequest);
            };
            litebox_broker_core::pipe::read(session, request.handle, request.length)
                .map_err(ErrorCode::from)
                .and_then(|data| {
                    shared
                        .memory
                        .write(offset, &data)
                        .map_err(|_| ErrorCode::Internal)?;
                    Ok(PipeResponse::ReadShared(ReadPipeSharedResponse {
                        read: data
                            .len()
                            .try_into()
                            .map_err(|_| ErrorCode::ResourceExhausted)?,
                    }))
                })
        }
        PipeRequest::Write(request) => {
            litebox_broker_core::pipe::write(session, request.handle, &request.data)
                .map_err(ErrorCode::from)
                .and_then(|written| {
                    Ok(PipeResponse::Write(WritePipeResponse {
                        written: written
                            .try_into()
                            .map_err(|_| ErrorCode::ResourceExhausted)?,
                    }))
                })
        }
        PipeRequest::WriteShared(request) => {
            let Some(shared) = pipe_shared_memories.get(&request.handle) else {
                return BrokerResponse::Error(ErrorCode::InvalidRights);
            };
            if shared.endpoint != SharedPipeEndpoint::Write {
                return BrokerResponse::Error(ErrorCode::InvalidRights);
            }
            let Some(offset) = shared_memory_offset(
                shared,
                PIPE_SHARED_MEMORY_REGION_SIZE,
                request.offset,
                request.length,
            ) else {
                return BrokerResponse::Error(ErrorCode::MalformedRequest);
            };
            let length = request.length as usize;
            let mut data = Vec::new();
            if data.try_reserve_exact(length).is_err() {
                return BrokerResponse::Error(ErrorCode::OutOfMemory);
            }
            data.resize(length, 0);
            if shared.memory.read(offset, &mut data).is_err() {
                return BrokerResponse::Error(ErrorCode::Internal);
            }
            litebox_broker_core::pipe::write(session, request.handle, &data)
                .map_err(ErrorCode::from)
                .and_then(|written| {
                    Ok(PipeResponse::WriteShared(WritePipeResponse {
                        written: written
                            .try_into()
                            .map_err(|_| ErrorCode::ResourceExhausted)?,
                    }))
                })
        }
    };

    match response {
        Ok(response) => BrokerResponse::Pipe(response),
        Err(error) => BrokerResponse::Error(error),
    }
}

fn shared_memory_offset<Memory: SharedMemory>(
    shared: &PipeSharedMemory<Memory>,
    base: usize,
    offset: u32,
    length: u32,
) -> Option<usize> {
    let offset = offset as usize;
    let length = length as usize;
    let end = offset.checked_add(length)?;
    if end > PIPE_SHARED_MEMORY_REGION_SIZE {
        return None;
    }
    let absolute = base.checked_add(offset)?;
    let absolute_end = absolute.checked_add(length)?;
    (absolute_end <= shared.memory.len()).then_some(absolute)
}

fn handle_event_request(session: &BrokerSession, request: EventRequest) -> BrokerResponse {
    match request {
        EventRequest::Create(request) => {
            match litebox_broker_core::event::create(session, request.initial_count) {
                Ok(handle) => {
                    BrokerResponse::Event(EventResponse::Create(CreateEventResponse { handle }))
                }
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
        EventRequest::Add(request) => {
            match litebox_broker_core::event::add(session, request.handle, request.value) {
                Ok(readiness) => {
                    BrokerResponse::Event(EventResponse::Add(AddEventResponse { readiness }))
                }
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
        EventRequest::Consume(request) => {
            match litebox_broker_core::event::consume(session, request.handle, request.mode) {
                Ok(consumption) => BrokerResponse::Event(EventResponse::Consume(consumption)),
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
    }
}

/// Terminal outcome after processing one broker connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionTermination {
    /// The peer cleanly closed the channel.
    PeerClosed,
    /// The broker sent a protocol-state error before closing the channel.
    ProtocolViolation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_core::{ObjectRights, PolicyEngine};
    use litebox_broker_protocol::event::{
        AddEventRequest, ConsumeEventRequest, CreateEventRequest, EventConsumeMode,
    };
    use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerNotification};
    use litebox_broker_protocol::pipe::{
        CreatePipeRequest, ReadPipeRequest, ReadPipeSharedRequest, WritePipeRequest,
        WritePipeSharedRequest,
    };
    use litebox_broker_protocol::shared_memory::{NoSharedMemory, SharedMemoryError};
    use litebox_broker_protocol::{ObjectHandle, ProtocolVersion};
    use std::sync::Mutex;

    #[test]
    fn host_request_handling_uses_one_broker_core() {
        let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .unwrap();

        serve_connection_negotiates_routes_one_request_and_returns_peer_closed(&broker);
        serve_connection_retries_after_version_mismatch(&broker);
        serve_connection_rejects_active_request_before_negotiation(&broker);
        serve_connection_rejects_handshake_request_after_negotiation(&broker);
        serve_connection_returns_channel_error_when_response_send_fails(&broker);
        serve_connection_returns_event_readiness_in_control_responses(&broker);
        active_request_closes_object_reference(&broker);
        shared_pipe_data_path_stages_bytes_and_validates_ranges(&broker);
        pipe_data_path_falls_back_to_inline_operations(&broker);
    }

    fn serve_connection_negotiates_routes_one_request_and_returns_peer_closed(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerRequest::Event(
                    EventRequest::Create(CreateEventRequest { initial_count: 0 }),
                ))),
                Ok(HostReceive::PeerClosed),
            ]),
        );
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses[0],
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }
        );
        let handle = match &channel.responses[0] {
            BrokerResponse::Event(EventResponse::Create(response)) => response.handle,
            response => panic!("unexpected response: {response:?}"),
        };
        assert_ne!(handle.0, 0);
    }

    fn serve_connection_retries_after_version_mismatch(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1),
                })),
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: BROKER_PROTOCOL_VERSION,
                })),
            ]),
            std::vec::Vec::from([Ok(HostReceive::PeerClosed)]),
        );
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses,
            [
                BrokerHandshakeResponse::VersionMismatch {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION
                },
                BrokerHandshakeResponse::Negotiated {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION
                }
            ]
        );
    }

    fn serve_connection_rejects_active_request_before_negotiation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::ProtocolViolation)]),
            std::vec::Vec::new(),
        );
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
            ConnectionTermination::ProtocolViolation
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::Error(ErrorCode::ProtocolState)]
        );
        assert!(channel.responses.is_empty());
    }

    fn serve_connection_rejects_handshake_request_after_negotiation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::ProtocolViolation)]),
        );
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
            ConnectionTermination::ProtocolViolation
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }]
        );
        assert_eq!(
            channel.responses,
            [BrokerResponse::Error(ErrorCode::ProtocolState)]
        );
    }

    fn serve_connection_returns_channel_error_when_response_send_fails(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::new(),
        );
        channel.send_error = true;
        let mut notifications = FakeHostNotificationChannel::default();

        match serve_connection(broker, &mut channel, &mut notifications) {
            Err(BrokerHostError::Channel(())) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert!(channel.handshake_responses.is_empty());
    }

    fn serve_connection_returns_event_readiness_in_control_responses(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerRequest::Event(
                EventRequest::Create(CreateEventRequest { initial_count: 0 }),
            )))]),
        );
        channel.enqueue_readiness_requests_after_create = true;
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert!(notifications.notifications.is_empty());
        assert_eq!(
            &channel.responses[1..],
            [
                BrokerResponse::Event(EventResponse::Add(AddEventResponse {
                    readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ
                        | litebox_broker_protocol::readiness::ReadinessFlags::WRITE,
                })),
                BrokerResponse::Event(EventResponse::Consume(
                    litebox_broker_protocol::event::ConsumeEventResponse {
                        value: 1,
                        readiness: litebox_broker_protocol::readiness::ReadinessFlags::WRITE,
                    }
                )),
            ]
        );
    }

    fn active_request_closes_object_reference(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let response = handle_test_request(
            &session,
            BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        );
        let BrokerResponse::Event(EventResponse::Create(response)) = response else {
            panic!("unexpected create response: {response:?}");
        };
        let handle = response.handle;

        assert_eq!(
            handle_test_request(&session, BrokerRequest::CloseObject(handle)),
            BrokerResponse::ObjectClosed
        );
        assert_eq!(
            handle_test_request(&session, BrokerRequest::CheckReadiness(handle)),
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
        assert_eq!(
            handle_test_request(
                &session,
                BrokerRequest::CloseObject(ObjectHandle(handle.0 + 1))
            ),
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
    }

    fn shared_pipe_data_path_stages_bytes_and_validates_ranges(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let mut channel = SharedMemoryHostControlChannel;
        let mut shared_memories = BTreeMap::new();
        let HandledResponse {
            response,
            shared_memory,
        } = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 64,
                atomic_write_size: 16,
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        let BrokerResponse::Pipe(PipeResponse::Create(response)) = response else {
            panic!("unexpected create response: {response:?}");
        };
        assert!(response.shared_memory);
        assert_eq!(shared_memories.len(), 2);
        let memory = shared_memory.unwrap();

        memory
            .write(PIPE_SHARED_MEMORY_REGION_SIZE + 7, &[1, 2, 3])
            .unwrap();
        let write = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::WriteShared(WritePipeSharedRequest {
                handle: response.write_handle,
                offset: 7,
                length: 3,
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        assert_eq!(
            write.response,
            BrokerResponse::Pipe(PipeResponse::WriteShared(WritePipeResponse { written: 3 }))
        );

        let read = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::ReadShared(ReadPipeSharedRequest {
                handle: response.read_handle,
                offset: 11,
                length: 3,
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        assert_eq!(
            read.response,
            BrokerResponse::Pipe(PipeResponse::ReadShared(ReadPipeSharedResponse { read: 3 }))
        );
        let mut data = [0; 3];
        memory.read(11, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3]);

        let wrong_endpoint = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::ReadShared(ReadPipeSharedRequest {
                handle: response.write_handle,
                offset: 0,
                length: 1,
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        assert_eq!(
            wrong_endpoint.response,
            BrokerResponse::Error(ErrorCode::InvalidRights)
        );
        let invalid_range = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::WriteShared(WritePipeSharedRequest {
                handle: response.write_handle,
                offset: (PIPE_SHARED_MEMORY_REGION_SIZE - 1).try_into().unwrap(),
                length: 2,
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        assert_eq!(
            invalid_range.response,
            BrokerResponse::Error(ErrorCode::MalformedRequest)
        );
    }

    fn pipe_data_path_falls_back_to_inline_operations(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let mut channel = FakeHostControlChannel::new(std::vec::Vec::new(), std::vec::Vec::new());
        let mut shared_memories = BTreeMap::new();
        let created = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 64,
                atomic_write_size: 16,
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        let BrokerResponse::Pipe(PipeResponse::Create(response)) = created.response else {
            panic!("unexpected create response: {:?}", created.response);
        };
        assert!(!response.shared_memory);
        assert!(created.shared_memory.is_none());

        let written = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::Write(WritePipeRequest {
                handle: response.write_handle,
                data: Vec::from([1, 2, 3]),
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        assert_eq!(
            written.response,
            BrokerResponse::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 }))
        );
        let read = handle_request(
            &session,
            BrokerRequest::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle: response.read_handle,
                length: 3,
            })),
            &mut channel,
            &mut shared_memories,
        )
        .unwrap();
        assert_eq!(
            read.response,
            BrokerResponse::Pipe(PipeResponse::Read(ReadPipeResponse {
                data: Vec::from([1, 2, 3])
            }))
        );
    }

    fn handle_test_request(session: &BrokerSession, request: BrokerRequest) -> BrokerResponse {
        let mut channel = FakeHostControlChannel::new(std::vec::Vec::new(), std::vec::Vec::new());
        handle_request(session, request, &mut channel, &mut BTreeMap::new())
            .unwrap()
            .response
    }

    struct FakeHostControlChannel {
        handshake_requests:
            std::vec::Vec<core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>>,
        requests: std::vec::Vec<core::result::Result<HostReceive<BrokerRequest>, ()>>,
        handshake_responses: std::vec::Vec<BrokerHandshakeResponse>,
        responses: std::vec::Vec<BrokerResponse>,
        enqueue_readiness_requests_after_create: bool,
        send_error: bool,
    }

    impl FakeHostControlChannel {
        fn new(
            handshake_requests: std::vec::Vec<
                core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>,
            >,
            requests: std::vec::Vec<core::result::Result<HostReceive<BrokerRequest>, ()>>,
        ) -> Self {
            Self {
                handshake_requests,
                requests,
                handshake_responses: std::vec::Vec::new(),
                responses: std::vec::Vec::new(),
                enqueue_readiness_requests_after_create: false,
                send_error: false,
            }
        }
    }

    impl HostControlChannel for FakeHostControlChannel {
        type Error = ();
        type SharedMemory = NoSharedMemory;

        fn peer_credential(&self) -> core::result::Result<PeerCredential, Self::Error> {
            Ok(PeerCredential::Unauthenticated)
        }

        fn recv_handshake_request(
            &mut self,
        ) -> core::result::Result<HostReceive<BrokerHandshakeRequest>, Self::Error> {
            if self.handshake_requests.is_empty() {
                Ok(HostReceive::PeerClosed)
            } else {
                self.handshake_requests.remove(0)
            }
        }

        fn send_handshake_response(
            &mut self,
            response: &BrokerHandshakeResponse,
        ) -> core::result::Result<(), Self::Error> {
            if self.send_error {
                return Err(());
            }
            self.handshake_responses.push(response.clone());
            Ok(())
        }

        fn recv_request(
            &mut self,
        ) -> core::result::Result<HostReceive<BrokerRequest>, Self::Error> {
            if self.requests.is_empty() {
                Ok(HostReceive::PeerClosed)
            } else {
                self.requests.remove(0)
            }
        }

        fn send_response(
            &mut self,
            response: &BrokerResponse,
            shared_memory: Option<&Self::SharedMemory>,
        ) -> core::result::Result<(), Self::Error> {
            assert!(shared_memory.is_none());
            if self.send_error {
                return Err(());
            }
            if self.enqueue_readiness_requests_after_create
                && let BrokerResponse::Event(EventResponse::Create(response)) = response
            {
                self.requests
                    .push(Ok(HostReceive::Message(BrokerRequest::Event(
                        EventRequest::Add(AddEventRequest {
                            handle: response.handle,
                            value: 1,
                        }),
                    ))));
                self.requests
                    .push(Ok(HostReceive::Message(BrokerRequest::Event(
                        EventRequest::Consume(ConsumeEventRequest {
                            handle: response.handle,
                            mode: EventConsumeMode::One,
                        }),
                    ))));
                self.requests.push(Ok(HostReceive::PeerClosed));
            }
            self.responses.push(response.clone());
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let source = memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct SharedMemoryHostControlChannel;

    impl HostControlChannel for SharedMemoryHostControlChannel {
        type Error = ();
        type SharedMemory = TestSharedMemory;

        fn peer_credential(&self) -> core::result::Result<PeerCredential, Self::Error> {
            Ok(PeerCredential::Unauthenticated)
        }

        fn recv_handshake_request(
            &mut self,
        ) -> core::result::Result<HostReceive<BrokerHandshakeRequest>, Self::Error> {
            panic!("unexpected handshake receive")
        }

        fn send_handshake_response(
            &mut self,
            _response: &BrokerHandshakeResponse,
        ) -> core::result::Result<(), Self::Error> {
            panic!("unexpected handshake response")
        }

        fn recv_request(
            &mut self,
        ) -> core::result::Result<HostReceive<BrokerRequest>, Self::Error> {
            panic!("unexpected request receive")
        }

        fn create_shared_memory(
            &mut self,
            length: usize,
        ) -> core::result::Result<Option<Self::SharedMemory>, Self::Error> {
            Ok(Some(TestSharedMemory::new(length)))
        }

        fn send_response(
            &mut self,
            _response: &BrokerResponse,
            _shared_memory: Option<&Self::SharedMemory>,
        ) -> core::result::Result<(), Self::Error> {
            panic!("unexpected response send")
        }
    }

    #[derive(Default)]
    struct FakeHostNotificationChannel {
        notifications: std::vec::Vec<BrokerNotification>,
    }

    impl HostNotificationChannel for FakeHostNotificationChannel {
        type Error = ();

        fn send_notification(
            &mut self,
            notification: &BrokerNotification,
        ) -> core::result::Result<(), Self::Error> {
            self.notifications.push(notification.clone());
            Ok(())
        }
    }
}
