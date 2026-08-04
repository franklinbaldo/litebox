// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{TimerfdRequest, TimerfdResponse};
use crate::readiness::ReadinessFlags;
use crate::timerfd::{
    CreateTimerfdRequest, CreateTimerfdResponse, GetTimerfdRequest, GetTimerfdResponse,
    ReadTimerfdRequest, ReadTimerfdResponse, SetTimerfdRequest, SetTimerfdResponse, TimerfdSpec,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

// Timerfd operation tags live with the timerfd family. Future timerfd
// operations should add tags here; unrelated object families get their own
// module.
const TIMERFD_REQUEST_TAG_CREATE: u8 = 0;
const TIMERFD_REQUEST_TAG_SET: u8 = 1;
const TIMERFD_REQUEST_TAG_GET: u8 = 2;
const TIMERFD_REQUEST_TAG_READ: u8 = 3;

const TIMERFD_RESPONSE_TAG_CREATE: u8 = 0;
const TIMERFD_RESPONSE_TAG_SET: u8 = 1;
const TIMERFD_RESPONSE_TAG_GET: u8 = 2;
const TIMERFD_RESPONSE_TAG_READ: u8 = 3;

fn encode_spec(encoder: &mut Encoder, spec: TimerfdSpec) {
    encoder.u64(spec.value_seconds);
    encoder.u64(spec.value_nanoseconds);
    encoder.u64(spec.interval_seconds);
    encoder.u64(spec.interval_nanoseconds);
}

fn decode_spec(decoder: &mut Decoder<'_>) -> Result<TimerfdSpec, WireError> {
    Ok(TimerfdSpec {
        value_seconds: decoder.u64()?,
        value_nanoseconds: decoder.u64()?,
        interval_seconds: decoder.u64()?,
        interval_nanoseconds: decoder.u64()?,
    })
}

pub(super) fn encode_timerfd_request(encoder: &mut Encoder, request: TimerfdRequest) {
    match request {
        TimerfdRequest::Create(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_CREATE);
            encoder.u32(request.clock_id.cast_unsigned());
        }
        TimerfdRequest::Set(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_SET);
            encoder.handle(request.handle);
            encoder.u32(request.flags);
            encode_spec(encoder, request.specification);
        }
        TimerfdRequest::Get(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_GET);
            encoder.handle(request.handle);
        }
        TimerfdRequest::Read(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_READ);
            encoder.handle(request.handle);
        }
    }
}

pub(super) fn decode_timerfd_request(
    decoder: &mut Decoder<'_>,
) -> Result<TimerfdRequest, WireError> {
    let request = match decoder.u8()? {
        TIMERFD_REQUEST_TAG_CREATE => TimerfdRequest::Create(CreateTimerfdRequest {
            clock_id: decoder.u32()?.cast_signed(),
        }),
        TIMERFD_REQUEST_TAG_SET => {
            let handle = decoder.handle()?;
            let flags = decoder.u32()?;
            TimerfdRequest::Set(SetTimerfdRequest {
                handle,
                flags,
                specification: decode_spec(decoder)?,
            })
        }
        TIMERFD_REQUEST_TAG_GET => TimerfdRequest::Get(GetTimerfdRequest {
            handle: decoder.handle()?,
        }),
        TIMERFD_REQUEST_TAG_READ => TimerfdRequest::Read(ReadTimerfdRequest {
            handle: decoder.handle()?,
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(request)
}

pub(super) fn encode_timerfd_response(encoder: &mut Encoder, response: TimerfdResponse) {
    match response {
        TimerfdResponse::Create(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_CREATE);
            encoder.handle(response.handle);
        }
        TimerfdResponse::Set(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_SET);
            encoder.u32(response.readiness.0);
            encode_spec(encoder, response.previous);
        }
        TimerfdResponse::Get(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_GET);
            encode_spec(encoder, response.current);
        }
        TimerfdResponse::Read(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_READ);
            encoder.u64(response.expirations);
            encoder.u32(response.readiness.0);
        }
    }
}

pub(super) fn decode_timerfd_response(
    decoder: &mut Decoder<'_>,
) -> Result<TimerfdResponse, WireError> {
    let response = match decoder.u8()? {
        TIMERFD_RESPONSE_TAG_CREATE => TimerfdResponse::Create(CreateTimerfdResponse {
            handle: decoder.handle()?,
        }),
        TIMERFD_RESPONSE_TAG_SET => {
            let readiness = ReadinessFlags(decoder.u32()?);
            TimerfdResponse::Set(SetTimerfdResponse {
                readiness,
                previous: decode_spec(decoder)?,
            })
        }
        TIMERFD_RESPONSE_TAG_GET => TimerfdResponse::Get(GetTimerfdResponse {
            current: decode_spec(decoder)?,
        }),
        TIMERFD_RESPONSE_TAG_READ => TimerfdResponse::Read(ReadTimerfdResponse {
            expirations: decoder.u64()?,
            readiness: ReadinessFlags(decoder.u32()?),
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(response)
}
