// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned platform timerfd authority.
//!
//! A broker timerfd delegates timekeeping to a host-owned Linux `timerfd`
//! descriptor. The broker core owns the object reference and readiness
//! registration; the host platform (via [`TimerfdProvider`]) owns the real
//! descriptor and publishes readiness when the timer expires, exactly like
//! broker sockets.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::timerfd::{CreateTimerfdRequest, TimerfdSpec};
use spin::Once;

use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result, SessionId};

/// Broker-wide timerfd provider supplied by the host platform.
///
/// The provider creates per-timer [`PlatformTimerfd`] resources and owns any
/// bookkeeping shared across a session's timers. Operations on an individual
/// timer belong to [`PlatformTimerfd`], not this shared provider.
pub trait TimerfdProvider: Send + Sync {
    /// Creates one host timerfd resource for an authenticated session.
    ///
    /// The returned timer must not retain authority beyond its `Arc` lifetime.
    fn create(
        &self,
        session_id: SessionId,
        request: CreateTimerfdRequest,
        readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformTimerfd>>;

    /// Releases provider state associated with a session after its references close.
    fn close_session(&self, session_id: SessionId);
}

/// One host timerfd resource created by [`TimerfdProvider`].
///
/// The broker retains this resource in an `Arc`, allowing an operation already
/// in flight to finish after its object handle closes. Dropping the final `Arc`
/// releases the host descriptor.
pub trait PlatformTimerfd: Send + Sync {
    /// Arms or disarms the timer, returning the setting previously in effect.
    ///
    /// An all-zero `value` in `specification` disarms the timer. Unsupported
    /// `flags` are rejected with [`BrokerError::UnsupportedOperation`].
    fn set(&self, specification: TimerfdSpec, flags: u32) -> Result<TimerfdSpec>;

    /// Returns the time remaining until the next expiration and the interval.
    fn get(&self) -> Result<TimerfdSpec>;

    /// Drains and returns the accumulated expiration count.
    ///
    /// A timer that has not expired since the last read returns
    /// [`BrokerError::WouldBlock`]. A successful read always returns `>= 1`.
    fn read(&self) -> Result<u64>;

    /// Returns the current readiness snapshot.
    fn readiness(&self) -> ReadinessFlags;
}

/// Placeholder provider for broker configurations that deliberately disable timers.
pub struct UnsupportedTimerfdProvider;

impl TimerfdProvider for UnsupportedTimerfdProvider {
    fn create(
        &self,
        _session_id: SessionId,
        _request: CreateTimerfdRequest,
        _readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformTimerfd>> {
        Err(BrokerError::UnsupportedOperation)
    }

    fn close_session(&self, _session_id: SessionId) {}
}

/// Creates a broker-owned timerfd.
///
/// The total number of live timers is bounded by the shared object-reference
/// limit; timers do not carry a separate per-resource quota.
pub fn create(
    session: &BrokerSession,
    request: CreateTimerfdRequest,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = session
        .core
        .policy
        .principal_object_rights(session.caller_credential)?;
    let reference = session.reserve_object_reference(rights)?;
    let guard = Arc::new(TimerfdReservation);
    let readiness =
        ReadinessRegistration::new_with_retirement_guard(reference.handle(), readiness_sink, guard);
    let resource = Arc::new(TimerfdResource {
        platform_timerfd: Once::new(),
        readiness,
    });
    let platform_timerfd = match session.core.timerfd_provider.create(
        session.session_id,
        request,
        resource.readiness.clone(),
    ) {
        Ok(timerfd) => timerfd,
        Err(error) => {
            // The provider may have retained its registration before failing,
            // so retirement cannot rely on the local clone being the last one.
            resource.readiness.retire();
            return Err(error);
        }
    };
    resource.platform_timerfd.call_once(|| platform_timerfd);
    let handle = reference.commit(ObjectEntry::Timerfd(TimerfdObject::new(resource)))?;
    Ok(handle)
}

/// Arms or disarms a broker-owned timerfd, returning the previous setting.
pub fn set(
    session: &BrokerSession,
    handle: ObjectHandle,
    specification: TimerfdSpec,
    flags: u32,
) -> Result<(TimerfdSpec, ReadinessFlags)> {
    let resource = timerfd_resource(session, handle, ObjectRights::WRITE)?;
    let previous = resource.set(specification, flags)?;
    Ok((previous, resource.readiness()))
}

/// Returns a broker-owned timerfd's current setting.
pub fn get(session: &BrokerSession, handle: ObjectHandle) -> Result<TimerfdSpec> {
    let resource = timerfd_resource(session, handle, ObjectRights::WAIT)?;
    resource.get()
}

/// Drains a broker-owned timerfd's accumulated expiration count.
pub fn read(session: &BrokerSession, handle: ObjectHandle) -> Result<(u64, ReadinessFlags)> {
    let resource = timerfd_resource(session, handle, ObjectRights::WAIT)?;
    let expirations = resource.read()?;
    Ok((expirations, resource.readiness()))
}

fn timerfd_resource(
    session: &BrokerSession,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<Arc<TimerfdResource>> {
    let object = session.authorized_object(handle, required_rights)?;
    let object = object.read();
    let ObjectEntry::Timerfd(timerfd) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok(timerfd.resource())
}

/// A broker-owned timerfd reference.
pub(crate) struct TimerfdObject {
    resource: Arc<TimerfdResource>,
}

impl TimerfdObject {
    fn new(resource: Arc<TimerfdResource>) -> Self {
        Self { resource }
    }

    pub(crate) fn resource(&self) -> Arc<TimerfdResource> {
        Arc::clone(&self.resource)
    }
}

pub(crate) struct TimerfdResource {
    platform_timerfd: Once<Arc<dyn PlatformTimerfd>>,
    readiness: ReadinessRegistration,
}

impl TimerfdResource {
    fn platform_timerfd(&self) -> &dyn PlatformTimerfd {
        self.platform_timerfd
            .get()
            .expect("committed timerfd resources are initialized")
            .as_ref()
    }

    fn set(&self, specification: TimerfdSpec, flags: u32) -> Result<TimerfdSpec> {
        self.platform_timerfd().set(specification, flags)
    }

    fn get(&self) -> Result<TimerfdSpec> {
        self.platform_timerfd().get()
    }

    fn read(&self) -> Result<u64> {
        self.platform_timerfd().read()
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.platform_timerfd().readiness()
    }
}

impl Drop for TimerfdResource {
    fn drop(&mut self) {
        self.readiness.retire();
    }
}

/// Retirement guard for a timerfd's readiness registration.
///
/// Timers are bounded by the shared object-reference limit rather than a
/// dedicated quota, so this guard carries no reservation state; it exists only
/// to satisfy the readiness registration's deferred-retirement contract.
struct TimerfdReservation;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::readiness::tests::TestReadinessSink;
    use crate::{BrokerCore, CallerCredential};
    use alloc::sync::Weak;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    const TEST_CLOCK_MONOTONIC: i32 = 1;

    fn create_request() -> CreateTimerfdRequest {
        CreateTimerfdRequest {
            clock_id: TEST_CLOCK_MONOTONIC,
        }
    }

    fn armed_spec() -> TimerfdSpec {
        TimerfdSpec {
            value_seconds: 0,
            value_nanoseconds: 500_000,
            interval_seconds: 0,
            interval_nanoseconds: 0,
        }
    }

    #[derive(Clone, Default)]
    pub(crate) struct TestTimerfdProvider {
        state: Arc<TestTimerfdState>,
    }

    #[derive(Default)]
    struct TestTimerfdState {
        creates: StdMutex<std::vec::Vec<(SessionId, CreateTimerfdRequest)>>,
        closed_sessions: StdMutex<std::vec::Vec<SessionId>>,
        dropped_timers: AtomicUsize,
        fail_create: core::sync::atomic::AtomicBool,
        live_timer: StdMutex<Option<Weak<TestPlatformTimerfd>>>,
    }

    impl TestTimerfdProvider {
        pub(crate) fn fail_next_create(&self) {
            self.state.fail_create.store(true, Ordering::Relaxed);
        }

        /// Simulates a host expiration on the most recently created live timer.
        fn fire_live(&self) {
            self.state
                .live_timer
                .lock()
                .unwrap()
                .as_ref()
                .and_then(Weak::upgrade)
                .expect("a live timer was created")
                .fire();
        }
    }

    impl TimerfdProvider for TestTimerfdProvider {
        fn create(
            &self,
            session_id: SessionId,
            request: CreateTimerfdRequest,
            readiness: ReadinessRegistration,
        ) -> Result<Arc<dyn PlatformTimerfd>> {
            self.state
                .creates
                .lock()
                .unwrap()
                .push((session_id, request));
            if self.state.fail_create.swap(false, Ordering::Relaxed) {
                return Err(BrokerError::OutOfMemory);
            }
            let timer = Arc::new(TestPlatformTimerfd {
                state: Arc::clone(&self.state),
                readiness,
                setting: StdMutex::new(TimerfdSpec::default()),
                pending: AtomicU64::new(0),
            });
            *self.state.live_timer.lock().unwrap() = Some(Arc::downgrade(&timer));
            Ok(timer)
        }

        fn close_session(&self, session_id: SessionId) {
            self.state.closed_sessions.lock().unwrap().push(session_id);
        }
    }

    struct TestPlatformTimerfd {
        state: Arc<TestTimerfdState>,
        readiness: ReadinessRegistration,
        setting: StdMutex<TimerfdSpec>,
        pending: AtomicU64,
    }

    impl TestPlatformTimerfd {
        /// Simulates a host expiration: accrues a count and publishes readiness.
        fn fire(&self) {
            self.pending.fetch_add(1, Ordering::Relaxed);
            self.readiness.publish(ReadinessFlags::READ).unwrap();
        }
    }

    impl PlatformTimerfd for TestPlatformTimerfd {
        fn set(&self, specification: TimerfdSpec, _flags: u32) -> Result<TimerfdSpec> {
            let mut setting = self.setting.lock().unwrap();
            let previous = *setting;
            *setting = specification;
            Ok(previous)
        }

        fn get(&self) -> Result<TimerfdSpec> {
            Ok(*self.setting.lock().unwrap())
        }

        fn read(&self) -> Result<u64> {
            let pending = self.pending.swap(0, Ordering::Relaxed);
            if pending == 0 {
                return Err(BrokerError::WouldBlock);
            }
            Ok(pending)
        }

        fn readiness(&self) -> ReadinessFlags {
            if self.pending.load(Ordering::Relaxed) > 0 {
                ReadinessFlags::READ
            } else {
                ReadinessFlags::default()
            }
        }
    }

    impl Drop for TestPlatformTimerfd {
        fn drop(&mut self) {
            self.state.dropped_timers.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn check_timerfd_lifecycle(broker: &BrokerCore, provider: &TestTimerfdProvider) {
        check_failed_create_rolls_back(broker, provider);
        check_timerfd_operations(broker, provider);
        check_wrong_object_type_is_rejected(broker, provider);
    }

    fn check_failed_create_rolls_back(broker: &BrokerCore, provider: &TestTimerfdProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        provider.fail_next_create();
        let sink = Arc::new(TestReadinessSink::default());
        assert_eq!(
            create(&session, create_request(), sink.clone()),
            Err(BrokerError::OutOfMemory)
        );
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
    }

    fn check_timerfd_operations(broker: &BrokerCore, provider: &TestTimerfdProvider) {
        let dropped_before = provider.state.dropped_timers.load(Ordering::Relaxed);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        let handle = create(&session, create_request(), sink.clone()).unwrap();

        // set returns the previous (zero) setting and re-arms.
        let (previous, _readiness) = set(&session, handle, armed_spec(), 0).unwrap();
        assert_eq!(previous, TimerfdSpec::default());
        assert_eq!(get(&session, handle).unwrap(), armed_spec());

        // A timer that has not expired reads as WouldBlock.
        assert_eq!(read(&session, handle), Err(BrokerError::WouldBlock));

        // Simulate a host expiration; readiness is published and the drained
        // count is reported.
        provider.fire_live();
        assert_eq!(
            session.check_readiness(handle).unwrap(),
            ReadinessFlags::READ
        );
        let (expirations, readiness) = read(&session, handle).unwrap();
        assert_eq!(expirations, 1);
        assert_eq!(readiness, ReadinessFlags::default());
        assert!(!sink.published.lock().unwrap().is_empty());

        session.close_object_reference(handle).unwrap();
        assert_eq!(
            provider.state.dropped_timers.load(Ordering::Relaxed),
            dropped_before + 1
        );
    }

    fn check_wrong_object_type_is_rejected(broker: &BrokerCore, _provider: &TestTimerfdProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let event = crate::event::create(&session, 0).unwrap();
        assert_eq!(
            set(&session, event, armed_spec(), 0),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(get(&session, event), Err(BrokerError::InvalidRights));
        assert_eq!(read(&session, event), Err(BrokerError::InvalidRights));
        session.close_object_reference(event).unwrap();
    }
}
