// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use crate::event::EventObject;
use crate::host_resource::{HostBackedObject, HostResourceId, HostResourceRetirement};
use crate::pipe::PipeObject;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::rwlock::RwLock;

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same session-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
    /// The trusted broker entry layer authenticated and bound the caller.
    HostGuaranteed,
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    Unauthenticated,
}

/// Broker-assigned session identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SessionId(pub u64);

bitflags::bitflags! {
    /// Broker rights attached to an object reference.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ObjectRights: u32 {
        /// Right to wait for readiness.
        const WAIT = 1 << 0;
        /// Right to mutate object state, such as adding event readiness credits.
        const WRITE = 1 << 1;
    }
}

pub(crate) struct ObjectReference {
    pub(crate) object: Arc<RwLock<ObjectEntry>>,
    pub(crate) session_id: SessionId,
    pub(crate) rights: ObjectRights,
}

pub(crate) enum ObjectEntry {
    Event(EventObject),
    Pipe(PipeObject),
    HostBacked(HostBackedObject),
}

/// Broker-owned authority token for one authenticated caller session.
///
/// User mode does not choose this value. The broker entry layer authenticates
/// the caller, then BrokerCore assigns this identity for all operations received
/// on that session. Dropping the session releases all object references it owns.
pub struct BrokerSession {
    pub(crate) core: BrokerCore,
    /// Broker-assigned session identity.
    pub(crate) session_id: SessionId,
    /// Broker-entry-authenticated caller credential for this session.
    pub(crate) caller_credential: CallerCredential,
    /// Host resources this session named and no longer references.
    ///
    /// Held behind an [`Arc`] so the host serving the session can keep
    /// draining it after the session is dropped, which is when teardown
    /// retires everything the session still referenced.
    retirement: Arc<HostResourceRetirement>,
}

impl BrokerSession {
    /// Creates an authenticated session identity.
    pub(crate) fn new(
        core: BrokerCore,
        session_id: SessionId,
        caller_credential: CallerCredential,
        retirement: Arc<HostResourceRetirement>,
    ) -> Self {
        Self {
            core,
            session_id,
            caller_credential,
            retirement,
        }
    }

    /// Returns the host resources this session has finished with.
    ///
    /// A host that names resources clones this before serving the
    /// session, drains it as it serves, and drains it once more after dropping
    /// the session, which retires everything the session still referenced.
    #[must_use]
    pub fn host_resource_retirement(&self) -> &Arc<HostResourceRetirement> {
        &self.retirement
    }

    /// Names a host-owned resource as a broker object.
    ///
    /// The session takes ownership only if this succeeds. A failure leaves the
    /// resource with the caller, which must release it, because admitting it
    /// far enough to retire it is exactly what the limit refused.
    ///
    /// An identity must be unique across the whole broker host, not merely
    /// within this session, until the host takes it back through
    /// [`HostResourceRetirement::take_retired`]: each session retires into its
    /// own queue, so naming one identity in two sessions passes every check
    /// here and retires it twice. The core treats identities as opaque and
    /// cannot tell two names apart, and a host that releases a
    /// descriptor twice may close an unrelated one that reused the number.
    pub fn adopt_host_resource(&self, resource: HostResourceId) -> Result<ObjectHandle> {
        self.create_object_reference_with(|| {
            self.retirement.try_charge()?;
            Ok(ObjectEntry::HostBacked(HostBackedObject::new(
                resource,
                Arc::clone(&self.retirement),
            )))
        })
    }

    /// Runs `f` on the host resource an authorized handle names.
    ///
    /// This is the only way out of the core for a host resource identity, and
    /// it is a lease rather than a getter because the identity is only
    /// meaningful while the object naming it is alive. The object is held for
    /// the duration of `f`, so within `f` the resource cannot be retired or
    /// released. Acting on the resource is therefore only safe inside `f`: an
    /// identity that escapes carries no such protection, and a concurrent
    /// close can retire it and let the host release the descriptor
    /// before the escaped copy is used, leaving that caller operating on
    /// whatever reused the number next. `f` must not let the identity outlive
    /// it, except to report which resource was named.
    ///
    /// The session that owns the handle is enforced here, so one session can
    /// never resolve another's resource; `required_rights` is the rights the
    /// caller intends to exercise, and the caller is responsible for asking for
    /// the rights the operation it is about to perform actually needs. A handle
    /// naming an object the core owns outright is not a host resource and is
    /// refused.
    ///
    /// `f` runs while the leased object is locked for reading, so it must not
    /// perform an operation that mutates a broker object, on this handle or any
    /// other: those take an object write lock, which self-deadlocks on this
    /// handle and risks a lock-order inversion between two threads holding
    /// leases on different objects. Closing references, naming resources, and
    /// draining retirement are all safe here. `f` should also confine itself to
    /// non-blocking work, since it holds a spin lock.
    pub fn with_host_resource<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(HostResourceId) -> Result<T>,
    ) -> Result<T> {
        self.with_authorized_object(handle, required_rights, |object| match object {
            ObjectEntry::HostBacked(host_backed) => f(host_backed.resource()),
            ObjectEntry::Event(_) | ObjectEntry::Pipe(_) => Err(BrokerError::InvalidRights),
        })
    }

    /// Checks that `additional` more references fit under the core limit.
    ///
    /// This bounds the reference table only. Host resources are bounded
    /// separately, by the charge [`HostResourceRetirement`] keeps, because a
    /// reference can be closed while an in-flight operation still holds the
    /// object it named: during that window the resource is absent from this
    /// table and not yet retired, so no count taken here could bound it.
    fn check_reference_capacity(
        &self,
        references: &HashMap<ObjectHandle, ObjectReference>,
        additional: usize,
    ) -> Result<()> {
        let admitted = references.len().checked_add(additional);
        if admitted.is_none_or(|admitted| admitted > self.core.limits.max_references) {
            return Err(BrokerError::ResourceExhausted);
        }
        Ok(())
    }

    pub(crate) fn create_object_reference(&self, object: ObjectEntry) -> Result<ObjectHandle> {
        self.create_object_reference_with(|| Ok(object))
    }

    /// Admits one reference and only then builds the object it names.
    ///
    /// The object is built inside the admitted path rather than by the caller
    /// because building a host-backed object is what makes it retirable: a
    /// refused adoption that had already built one would drop it, queue its
    /// resource for retirement, and push retirement past the capacity the
    /// refusal was protecting.
    fn create_object_reference_with(
        &self,
        object: impl FnOnce() -> Result<ObjectEntry>,
    ) -> Result<ObjectHandle> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let mut references = self.core.references.write();
        self.check_reference_capacity(&references, 1)?;
        let handle = self.core.allocate_reference_handle()?;
        let object = object()?;
        references.insert(
            handle,
            ObjectReference {
                object: Arc::new(RwLock::new(object)),
                session_id: self.session_id,
                rights,
            },
        );

        Ok(handle)
    }

    pub(crate) fn create_object_reference_pair(
        &self,
        first: ObjectEntry,
        second: ObjectEntry,
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let mut references = self.core.references.write();
        self.check_reference_capacity(&references, 2)?;
        let (first_handle, second_handle) = self.core.allocate_reference_handle_pair()?;
        for (handle, object) in [(first_handle, first), (second_handle, second)] {
            references.insert(
                handle,
                ObjectReference {
                    object: Arc::new(RwLock::new(object)),
                    session_id: self.session_id,
                    rights,
                },
            );
        }
        Ok((first_handle, second_handle))
    }

    pub(crate) fn with_authorized_object<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(&ObjectEntry) -> Result<T>,
    ) -> Result<T> {
        let object = {
            let references = self.core.references.read();
            self.authorize_use_object(&references, handle, required_rights)?
        };
        let object = object.read();
        f(&object)
    }

    pub(crate) fn with_authorized_object_mut<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(&mut ObjectEntry) -> Result<T>,
    ) -> Result<T> {
        let object = {
            let references = self.core.references.read();
            self.authorize_use_object(&references, handle, required_rights)?
        };
        let mut object = object.write();
        f(&mut object)
    }

    /// Returns the current readiness of a broker-owned object.
    pub fn check_readiness(&self, handle: ObjectHandle) -> Result<ReadinessFlags> {
        self.with_authorized_object(handle, ObjectRights::WAIT, |object| {
            match object {
                ObjectEntry::Event(event) => Ok(event.readiness()),
                ObjectEntry::Pipe(pipe) => Ok(pipe.readiness()),
                // Readiness of a host-backed object lives in the host that
                // owns it, so the core cannot answer. This reports the
                // same mismatch every other operation reports for the wrong
                // kind of object, because `UnsupportedOperation` reaches the
                // guest as an unrecoverable error and aborts it.
                ObjectEntry::HostBacked(_) => Err(BrokerError::InvalidRights),
            }
        })
    }

    fn authorize_use_object(
        &self,
        references: &HashMap<ObjectHandle, ObjectReference>,
        handle: ObjectHandle,
        required_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.session_id != self.session_id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.contains(required_rights) {
            return Err(BrokerError::InvalidRights);
        }
        let object = Arc::clone(&reference.object);
        Ok(object)
    }

    /// Closes one object reference owned by this session.
    ///
    /// The underlying object is released when this was the last live reference.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let mut references = self.core.references.write();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.session_id != self.session_id {
            return Err(BrokerError::UnknownObject);
        }
        references.remove(&handle);
        Ok(())
    }
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        self.core.close_session(self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use crate::host_resource::HostResourceId;
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine,
    };
    use alloc::sync::Arc;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
    use litebox_broker_protocol::readiness::ReadinessFlags;

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            BrokerCoreLimits::new(2, 4),
        )
        .unwrap();

        check_event_reference_lifecycle(&broker);
        check_session_drop_releases_references(&broker);
        check_pipe_lifecycle(&broker);
        check_pipe_reader_closure(&broker);
        check_host_resource_retirement(&broker);
        check_session_teardown_retires_host_resources(&broker);
        check_unreleased_resources_hold_their_capacity(&broker);
        check_in_flight_resources_hold_their_capacity(&broker);
        check_host_resource_naming_is_authorized(&broker);
        check_pair_handle_exhaustion(&broker);

        assert!(broker.references.read().is_empty());
    }

    fn check_event_reference_lifecycle(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = crate::event::create(&session, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0 + 1);

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            session.check_readiness(unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(session.check_readiness(handle), Ok(ReadinessFlags::WRITE));
        assert_eq!(
            crate::event::add(&session, handle, 1),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            crate::event::consume(&session, handle, EventConsumeMode::One),
            Ok(EventConsumption {
                value: 1,
                readiness: ReadinessFlags::WRITE,
            })
        );
        let second_handle = crate::event::create(&session, 0).unwrap();
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            crate::pipe::create(&session, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(session.close_object_reference(second_handle), Ok(()));

        assert_eq!(session.close_object_reference(handle), Ok(()));
        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );
    }

    fn check_session_drop_releases_references(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _handle = crate::event::create(&session, 0).unwrap();
        {
            let references = broker.references.read();
            assert_eq!(references.len(), 1);
        }

        drop(session);

        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
    }

    fn check_pipe_lifecycle(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&session, 5, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let (reader, writer) = crate::pipe::create(&session, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            session.check_readiness(reader),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 1),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(crate::pipe::write(&session, writer, &[1, 2]), Ok(2));
        assert_eq!(crate::pipe::write(&session, writer, &[3, 4, 5]), Ok(2));
        assert_eq!(
            crate::pipe::write(&session, writer, &[5]),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 3),
            Ok(std::vec::Vec::from([1, 2, 3]))
        );
        assert_eq!(crate::pipe::write(&session, writer, &[5, 6]), Ok(2));
        assert_eq!(session.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            session.check_readiness(reader),
            Ok(ReadinessFlags::READ | ReadinessFlags::HANGUP)
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 4),
            Ok(std::vec::Vec::from([4, 5, 6]))
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 1),
            Ok(std::vec::Vec::new())
        );
        assert_eq!(session.close_object_reference(reader), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_reader_closure(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = crate::pipe::create(&session, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(session.close_object_reference(reader), Ok(()));
        assert_eq!(crate::pipe::write(&session, writer, &[]), Ok(0));
        assert_eq!(
            crate::pipe::write(&session, writer, &[1]),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(
            session.check_readiness(writer),
            Ok(ReadinessFlags::WRITE | ReadinessFlags::ERROR)
        );
        assert_eq!(session.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_host_resource_retirement(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let retirement = Arc::clone(session.host_resource_retirement());
        let resource = HostResourceId(41);
        let handle = session.adopt_host_resource(resource).unwrap();

        assert_eq!(
            session.with_host_resource(handle, ObjectRights::WAIT, Ok),
            Ok(resource)
        );
        // The lease holds the object, so a resource cannot be retired while a
        // caller is acting on it.
        assert_eq!(
            session.with_host_resource(handle, ObjectRights::WAIT, |named| {
                session.close_object_reference(handle)?;
                assert_eq!(retirement.take_retired(), None);
                Ok(named)
            }),
            Ok(resource)
        );
        assert_eq!(retirement.take_retired(), Some(resource));
        let handle = session.adopt_host_resource(resource).unwrap();
        // Readiness belongs to the host that owns the resource, so the
        // core refuses rather than inventing an answer, and it refuses the way
        // a guest can recover from.
        assert_eq!(
            session.check_readiness(handle),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(retirement.take_retired(), None);

        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(retirement.take_retired(), Some(resource));
        assert_eq!(retirement.take_retired(), None);
    }

    fn check_session_teardown_retires_host_resources(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let retirement = Arc::clone(session.host_resource_retirement());
        let first = session.adopt_host_resource(HostResourceId(51)).unwrap();
        let second = session.adopt_host_resource(HostResourceId(52)).unwrap();
        assert_ne!(first, second);

        // Retirement state outlives the session, which is what lets a
        // host release resources the session never closed explicitly.
        drop(session);

        let mut retired = [
            retirement.take_retired().unwrap(),
            retirement.take_retired().unwrap(),
        ];
        retired.sort_unstable();
        assert_eq!(retired, [HostResourceId(51), HostResourceId(52)]);
        assert_eq!(retirement.take_retired(), None);
    }

    fn check_unreleased_resources_hold_their_capacity(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let retirement = Arc::clone(session.host_resource_retirement());
        let first = session.adopt_host_resource(HostResourceId(61)).unwrap();
        let second = session.adopt_host_resource(HostResourceId(62)).unwrap();

        // A refused naming leaves the resource with the caller instead of
        // queueing it, because queueing what the limit just refused is what
        // would let retirement state outgrow the capacity reserved for it.
        assert_eq!(
            session.adopt_host_resource(HostResourceId(63)),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(retirement.take_retired(), None);

        assert_eq!(session.close_object_reference(first), Ok(()));
        assert_eq!(session.close_object_reference(second), Ok(()));

        // Both references are gone, but nothing has released the resources they
        // named, so they still hold the capacity that bounds retirement state.
        assert_eq!(
            session.adopt_host_resource(HostResourceId(63)),
            Err(BrokerError::ResourceExhausted)
        );

        assert!(retirement.take_retired().is_some());
        assert!(retirement.take_retired().is_some());
        let handle = session.adopt_host_resource(HostResourceId(63)).unwrap();
        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(retirement.take_retired(), Some(HostResourceId(63)));
    }

    fn check_in_flight_resources_hold_their_capacity(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let retirement = Arc::clone(session.host_resource_retirement());
        let in_flight = HostResourceId(71);
        let handle = session.adopt_host_resource(in_flight).unwrap();

        // What an in-flight operation holds: every request clones the object
        // out of the reference table and then works without the table lock.
        let operand = {
            let references = broker.references.read();
            session
                .authorize_use_object(&references, handle, ObjectRights::WAIT)
                .unwrap()
        };
        assert_eq!(session.close_object_reference(handle), Ok(()));

        // The resource is now in neither the reference table nor the retirement
        // queue, so only the charge it still holds keeps the session from
        // naming more resources than the queue reserved room for.
        assert_eq!(retirement.take_retired(), None);
        let other = session.adopt_host_resource(HostResourceId(72)).unwrap();
        assert_eq!(
            session.adopt_host_resource(HostResourceId(73)),
            Err(BrokerError::ResourceExhausted)
        );

        drop(operand);
        assert_eq!(retirement.take_retired(), Some(in_flight));
        assert_eq!(session.close_object_reference(other), Ok(()));
        assert_eq!(retirement.take_retired(), Some(HostResourceId(72)));
    }

    fn check_host_resource_naming_is_authorized(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = session.adopt_host_resource(HostResourceId(71)).unwrap();
        let event = crate::event::create(&session, 0).unwrap();

        // Naming runs the same session check every operation runs, so one
        // session cannot reach another session's host resource.
        assert_eq!(
            other.with_host_resource(handle, ObjectRights::WAIT, Ok),
            Err(BrokerError::UnknownObject)
        );
        // An object the core owns outright has no host resource to name.
        assert_eq!(
            session.with_host_resource(event, ObjectRights::WAIT, Ok),
            Err(BrokerError::InvalidRights)
        );

        let retirement = Arc::clone(session.host_resource_retirement());
        drop(session);
        assert_eq!(retirement.take_retired(), Some(HostResourceId(71)));
    }

    fn check_pair_handle_exhaustion(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX - 1;
        }
        assert_eq!(
            crate::pipe::create(&session, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(*broker.next_reference_handle.read(), u64::MAX - 1);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let handle = crate::event::create(&session, 0).unwrap();
        assert_eq!(handle, ObjectHandle(u64::MAX - 1));
        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
    }
}
