// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ProtocolVersion;
use crate::error::ErrorCode;
use crate::event::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse,
    CreateEventRequest, CreateEventResponse, WaitEventRequest, WaitEventResponse,
};

/// Broker request sent over the control channel.
///
/// Connection-level protocol operations and broker object operation families live
/// at this layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerRequest {
    /// Protocol negotiation request.
    Negotiate {
        /// Required protocol version.
        protocol_version: ProtocolVersion,
    },
    /// Event object request family.
    Event(EventRequest),
}

/// Broker-owned event object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventRequest {
    /// Create a broker-owned event object.
    Create(CreateEventRequest),
    /// Check whether an event wait would complete now.
    Wait(WaitEventRequest),
    /// Add readiness credits to an event.
    Add(AddEventRequest),
    /// Consume readiness credits from an event.
    Consume(ConsumeEventRequest),
}

/// Broker response sent over the control channel.
///
/// Connection-level protocol outcomes and broker object operation families live
/// at this layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerResponse {
    /// Negotiation result.
    Negotiated {
        /// Broker protocol version supported by this endpoint.
        ///
        /// The broker returns its supported version after validating that the
        /// requested version matches it.
        broker_protocol_version: ProtocolVersion,
    },
    /// Negotiation failed because the requested version is unsupported.
    ///
    /// The connection remains in negotiation state and the local peer may retry
    /// with a compatible version using the broker-supported version advertised
    /// here.
    VersionMismatch {
        /// Broker protocol version supported by this endpoint.
        broker_protocol_version: ProtocolVersion,
    },
    /// Event object response family.
    Event(EventResponse),
    /// Operation failed with an ABI-neutral broker error.
    Error(ErrorCode),
}

/// Broker-owned event object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventResponse {
    /// Create operation response.
    Create(CreateEventResponse),
    /// Wait operation response.
    Wait(WaitEventResponse),
    /// Add operation response.
    Add(AddEventResponse),
    /// Consume operation response.
    Consume(ConsumeEventResponse),
}
