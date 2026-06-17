// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use crate::event::EventObject;
use crate::identity::{BrokerSession, CallerCredential, SessionId};
use crate::{BrokerCore, BrokerCoreState, BrokerError, Result};
use litebox_broker_protocol::ObjectHandle;
use slotmap::{Key, KeyData};
use spin::rwlock::RwLock;

/// Broker object type known to the authority core and policy engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectType {
    /// Broker-owned event object.
    Event,
}

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

slotmap::new_key_type! {
    /// Broker-owned object identifier.
    pub(crate) struct ObjectId;
    pub(crate) struct ObjectReferenceKey;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectReference {
    pub(crate) object_id: ObjectId,
    pub(crate) session_id: SessionId,
    pub(crate) rights: ObjectRights,
}

impl From<ObjectReferenceKey> for ObjectHandle {
    fn from(key: ObjectReferenceKey) -> Self {
        Self(key.data().as_ffi())
    }
}

impl TryFrom<ObjectHandle> for ObjectReferenceKey {
    type Error = BrokerError;

    fn try_from(handle: ObjectHandle) -> crate::Result<Self> {
        let key: Self = KeyData::from_ffi(handle.0).into();
        if ObjectHandle::from(key) == handle {
            Ok(key)
        } else {
            Err(BrokerError::UnknownObject)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectEntry {
    Event(EventObject),
}

impl ObjectEntry {
    pub(crate) const fn object_type(&self) -> ObjectType {
        match self {
            Self::Event(_) => ObjectType::Event,
        }
    }
}

pub(super) fn create_object_with_reference(
    session: &BrokerSession,
    object: ObjectEntry,
) -> Result<ObjectHandle> {
    let mut state = session.core.state.write();
    let object_type = object.object_type();
    let rights = state
        .policy
        .authorize_create_object(session.caller_credential, object_type)?;

    if state.objects.len() >= state.limits.max_objects
        || state.references.len() >= state.limits.max_references
    {
        return Err(BrokerError::ResourceExhausted);
    }
    if state.objects.len() == state.objects.capacity() {
        state
            .objects
            .try_reserve(1)
            .map_err(|_| BrokerError::ResourceExhausted)?;
    }
    if state.references.len() == state.references.capacity() {
        state
            .references
            .try_reserve(1)
            .map_err(|_| BrokerError::ResourceExhausted)?;
    }

    let object_id = state.objects.insert(Arc::new(RwLock::new(object)));
    let reference_key = state.references.insert(ObjectReference {
        object_id,
        session_id: session.session_id,
        rights,
    });

    Ok(reference_key.into())
}

pub(super) fn with_authorized_object<T>(
    session: &BrokerSession,
    handle: ObjectHandle,
    object_type: ObjectType,
    rights: ObjectRights,
    f: impl FnOnce(&ObjectEntry, ObjectRights) -> Result<T>,
) -> Result<T> {
    let authorized = {
        let state = session.core.state.read();
        authorize_use_object(
            &state,
            session.session_id,
            session.caller_credential,
            handle,
            object_type,
            rights,
        )?
    };
    let object = authorized.object.read();
    f(&object, authorized.rights)
}

pub(super) fn with_authorized_object_mut<T>(
    session: &BrokerSession,
    handle: ObjectHandle,
    object_type: ObjectType,
    rights: ObjectRights,
    f: impl FnOnce(&mut ObjectEntry, ObjectRights) -> Result<T>,
) -> Result<T> {
    let authorized = {
        let state = session.core.state.read();
        authorize_use_object(
            &state,
            session.session_id,
            session.caller_credential,
            handle,
            object_type,
            rights,
        )?
    };
    let mut object = authorized.object.write();
    f(&mut object, authorized.rights)
}

fn authorize_use_object(
    state: &BrokerCoreState,
    session_id: SessionId,
    caller_credential: CallerCredential,
    handle: ObjectHandle,
    object_type: ObjectType,
    rights: ObjectRights,
) -> Result<AuthorizedObject> {
    let reference = validate_handle(state, session_id, handle, object_type, rights)?;
    let reference_rights = reference.rights;
    let object = state
        .objects
        .get(reference.object_id)
        .ok_or(BrokerError::UnknownObject)?;
    state
        .policy
        .authorize_use_object(caller_credential, object_type, rights)?;
    Ok(AuthorizedObject {
        object: Arc::clone(object),
        rights: reference_rights,
    })
}

pub(super) fn close_object_reference(session: &BrokerSession, handle: ObjectHandle) -> Result<()> {
    let mut state = session.core.state.write();
    let object_id = reference_for_handle(&state, session.session_id, handle)?.object_id;
    if !state.objects.contains_key(object_id) {
        return Err(BrokerError::UnknownObject);
    }

    state.references.remove(handle.try_into()?);
    drop_object_if_unreferenced(&mut state, object_id);
    Ok(())
}

pub(super) fn drop_references_for_session(core: &BrokerCore, session_id: SessionId) {
    let mut state = core.state.write();
    let BrokerCoreState {
        objects,
        references,
        ..
    } = &mut *state;
    references.retain(|_, reference| reference.session_id != session_id);
    objects.retain(|object_id, _| {
        references
            .values()
            .any(|reference| reference.object_id == object_id)
    });
}

fn validate_handle(
    state: &BrokerCoreState,
    session_id: SessionId,
    handle: ObjectHandle,
    expected_type: ObjectType,
    required_rights: ObjectRights,
) -> Result<ObjectReference> {
    let reference = reference_for_handle(state, session_id, handle)?;
    if !reference.rights.contains(required_rights) {
        return Err(BrokerError::InvalidRights);
    }

    let object = state
        .objects
        .get(reference.object_id)
        .ok_or(BrokerError::UnknownObject)?;
    if object.read().object_type() != expected_type {
        return Err(BrokerError::WrongObjectType);
    }

    Ok(*reference)
}

fn reference_for_handle(
    state: &BrokerCoreState,
    session_id: SessionId,
    handle: ObjectHandle,
) -> Result<&ObjectReference> {
    let reference = state
        .references
        .get(handle.try_into()?)
        .ok_or(BrokerError::UnknownObject)?;
    if reference.session_id != session_id {
        return Err(BrokerError::UnknownObject);
    }
    Ok(reference)
}

fn drop_object_if_unreferenced(state: &mut BrokerCoreState, object_id: ObjectId) {
    if !state
        .references
        .values()
        .any(|reference| reference.object_id == object_id)
    {
        state.objects.remove(object_id);
    }
}

struct AuthorizedObject {
    object: Arc<RwLock<ObjectEntry>>,
    pub(crate) rights: ObjectRights,
}

#[cfg(test)]
mod tests {
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, PolicyEngine, allocate_id,
        event,
    };
    use litebox_broker_protocol::{ObjectHandle, WaitOutcome};

    #[test]
    fn allocator_exhausts_before_id_overflow() {
        let mut next_id = u64::MAX;

        assert_eq!(
            allocate_id(&mut next_id),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            allocate_id(&mut next_id),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn oversized_slotmap_limits_are_rejected_before_core_construction() {
        let too_many_entries = u32::MAX as usize;

        assert!(matches!(
            BrokerCore::new_with_limits(
                PolicyEngine::event_only(),
                BrokerCoreLimits::new(too_many_entries, 1)
            ),
            Err(BrokerError::ResourceExhausted)
        ));
        assert!(matches!(
            BrokerCore::new_with_limits(
                PolicyEngine::event_only(),
                BrokerCoreLimits::new(1, too_many_entries)
            ),
            Err(BrokerError::ResourceExhausted)
        ));
    }

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let core = BrokerCore::new(PolicyEngine::event_only()).unwrap();
        let session = core
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = core
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = event::create(&session, 0).unwrap();
        let noncanonical = ObjectHandle(handle.0 & u64::from(u32::MAX));

        assert_ne!(noncanonical, handle);
        assert_eq!(
            event::wait(&session, noncanonical),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert!(matches!(
            event::wait(&session, handle),
            Ok(WaitOutcome::WouldBlock(_))
        ));

        assert_eq!(session.close_object_reference(handle), Ok(()));
        {
            let state = core.state.read();
            assert!(state.references.is_empty());
            assert!(state.objects.is_empty());
        }
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        let session = core
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _handle = event::create(&session, 0).unwrap();
        {
            let state = core.state.read();
            assert_eq!(state.references.len(), 1);
            assert_eq!(state.objects.len(), 1);
        }

        drop(session);

        let state = core.state.read();
        assert!(state.references.is_empty());
        assert!(state.objects.is_empty());
    }
}
