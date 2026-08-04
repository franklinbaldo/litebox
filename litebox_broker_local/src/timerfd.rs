// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, TimerfdRequest, TimerfdResponse,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::timerfd::{
    CreateTimerfdRequest, GetTimerfdRequest, ReadTimerfdRequest, SetTimerfdRequest, TimerfdSpec,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned timerfd for the given clock.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_timerfd(&self, clock_id: i32) -> Result<ObjectHandle, Channel::Error> {
        let response =
            self.request_timerfd(TimerfdRequest::Create(CreateTimerfdRequest { clock_id }))?;
        let TimerfdResponse::Create(response) = response else {
            panic!("broker returned unexpected timerfd create response: {response:?}");
        };
        Ok(response.handle)
    }

    /// Arms or disarms a broker-owned timerfd, returning the previous setting.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn set_timerfd(
        &self,
        handle: ObjectHandle,
        specification: TimerfdSpec,
        flags: u32,
    ) -> Result<(TimerfdSpec, ReadinessFlags), Channel::Error> {
        let response = self.request_timerfd(TimerfdRequest::Set(SetTimerfdRequest {
            handle,
            specification,
            flags,
        }))?;
        let TimerfdResponse::Set(response) = response else {
            panic!("broker returned unexpected timerfd set response: {response:?}");
        };
        Ok((response.previous, response.readiness))
    }

    /// Reads a broker-owned timerfd's current setting.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn get_timerfd(&self, handle: ObjectHandle) -> Result<TimerfdSpec, Channel::Error> {
        let response = self.request_timerfd(TimerfdRequest::Get(GetTimerfdRequest { handle }))?;
        let TimerfdResponse::Get(response) = response else {
            panic!("broker returned unexpected timerfd get response: {response:?}");
        };
        Ok(response.current)
    }

    /// Drains a broker-owned timerfd's accumulated expiration count.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn read_timerfd(
        &self,
        handle: ObjectHandle,
    ) -> Result<(u64, ReadinessFlags), Channel::Error> {
        let response = self.request_timerfd(TimerfdRequest::Read(ReadTimerfdRequest { handle }))?;
        let TimerfdResponse::Read(response) = response else {
            panic!("broker returned unexpected timerfd read response: {response:?}");
        };
        Ok((response.expirations, response.readiness))
    }

    fn request_timerfd(&self, request: TimerfdRequest) -> Result<TimerfdResponse, Channel::Error> {
        match self.request(BrokerOperation::Timerfd(request))? {
            BrokerResult::Timerfd(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResult::ObjectClosed
            | BrokerResult::Readiness(_)
            | BrokerResult::Event(_)
            | BrokerResult::Pipe(_)
            | BrokerResult::Socket(_)) => {
                panic!("broker returned unexpected timerfd response: {response:?}");
            }
        }
    }
}
