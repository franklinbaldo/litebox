// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Naming and retirement for broker objects backed by host resources.
//!
//! Events and pipes keep every byte of their state inside this crate, so
//! dropping the last reference to one releases everything it owned. A socket
//! will not: its concrete state is a host descriptor and a poll registration
//! owned by the broker host, neither of which this crate can name or touch.
//! This module gives it an opaque name for such a resource and a way to hand
//! that name back once the last reference to it is gone, so the host can
//! release what this crate cannot.

use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::rwlock::RwLock;

use crate::{BrokerError, Result};

/// Opaque identity of one resource owned by the broker host.
///
/// The host allocates these and maps them to whatever it actually owns.
/// This type is deliberately absent from `litebox_broker_protocol`, so it
/// cannot be placed in a protocol message and cannot reach a local endpoint:
/// the local side names broker objects by [`ObjectHandle`] and never learns
/// what backs one.
///
/// [`ObjectHandle`]: litebox_broker_protocol::ObjectHandle
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostResourceId(pub u64);

#[derive(Debug)]
struct RetirementState {
    /// Retired identities the host has not taken back yet.
    retired: Vec<HostResourceId>,
    /// Resources this session named that the host has not released.
    ///
    /// This counts a resource from the moment the core names it until the
    /// host takes it back, which spans three states a resource passes
    /// through: reachable through the reference table, unreachable but still
    /// alive behind an in-flight operation that cloned the reference, and
    /// retired but not yet taken. Counting the whole span is what makes the
    /// bound below hold; counting reference-table membership would not, since
    /// a reference can be closed while an operation still holds the object.
    charged: usize,
}

/// Resources a session named on the host's behalf, and those whose last
/// reference is gone and that the host has not released yet.
///
/// One of these belongs to each session, and the host serving that session
/// drains it. Retirement is deferred rather than immediate because a
/// reference is dropped while the core holds the process-wide reference lock:
/// releasing a host resource closes descriptors and deregisters pollers, and
/// running that under a spin lock every request worker contends for would burn
/// host CPU for the length of a syscall. Recording the identity there is O(1),
/// and the host releases it after the lock is gone.
#[derive(Debug)]
pub struct HostResourceRetirement {
    state: RwLock<RetirementState>,
    /// The most resources this session may have outstanding at once.
    ///
    /// Naming a resource is refused past this, which is what keeps `retired`
    /// within the capacity reserved for it: a retired resource is still
    /// charged, so the queue can never grow beyond the number of resources
    /// admitted at once.
    capacity: usize,
}

impl HostResourceRetirement {
    /// Creates retirement state for a session allowed `capacity` resources.
    pub(crate) fn with_capacity(capacity: usize) -> Result<Arc<Self>> {
        let mut retired = Vec::new();
        retired
            .try_reserve_exact(capacity)
            .map_err(|_| BrokerError::OutOfMemory)?;
        Ok(Arc::new(Self {
            state: RwLock::new(RetirementState {
                retired,
                charged: 0,
            }),
            capacity,
        }))
    }

    /// Admits one more resource, or refuses if the session is already at its
    /// limit.
    ///
    /// Charging before the resource exists is what makes [`Self::retire`]
    /// infallible: the charge reserves the queue slot the resource will
    /// eventually occupy, and holds it for as long as the host owns the
    /// resource.
    pub(crate) fn try_charge(&self) -> Result<()> {
        let mut state = self.state.write();
        if state.charged >= self.capacity {
            return Err(BrokerError::ResourceExhausted);
        }
        state.charged += 1;
        Ok(())
    }

    /// Records that the last reference to `resource` is gone.
    ///
    /// This never allocates and never fails, which it must not, because it runs
    /// in `Drop`: a failure could not be reported and a lost identity would
    /// leak a host resource for the lifetime of the broker. The reservation
    /// made when the resource was charged is still held, so the push below
    /// always fits.
    fn retire(&self, resource: HostResourceId) {
        let mut state = self.state.write();
        debug_assert!(
            state.retired.len() < state.charged,
            "a retiring resource must still hold the charge it was admitted under"
        );
        state.retired.push(resource);
    }

    /// Takes back one resource waiting to be released, if any.
    ///
    /// The caller assumes sole responsibility for releasing what this returns:
    /// nothing tracks the identity afterwards, so a caller that discards a
    /// `Some` leaks the underlying host resource for the lifetime of the
    /// broker. Call this only where the resource is released unconditionally,
    /// never on a path that can drop the value.
    ///
    /// Callers release each resource after this returns rather than under a
    /// callback, so releasing one never runs while this lock is held. Order is
    /// unspecified; resources are independent and each is released once.
    #[must_use]
    pub fn take_retired(&self) -> Option<HostResourceId> {
        let mut state = self.state.write();
        let resource = state.retired.pop()?;
        state.charged -= 1;
        Some(resource)
    }
}

/// A broker object whose concrete state belongs to the host.
///
/// The core knows only the identity and returns it for retirement when the
/// last reference is dropped, which covers an explicit close, session teardown,
/// and a reference still held by an in-flight request alike.
pub(crate) struct HostBackedObject {
    resource: HostResourceId,
    retirement: Arc<HostResourceRetirement>,
}

impl HostBackedObject {
    /// Names `resource`, which must already be charged to `retirement`.
    pub(crate) fn new(resource: HostResourceId, retirement: Arc<HostResourceRetirement>) -> Self {
        Self {
            resource,
            retirement,
        }
    }

    pub(crate) fn resource(&self) -> HostResourceId {
        self.resource
    }
}

impl Drop for HostBackedObject {
    fn drop(&mut self) {
        self.retirement.retire(self.resource);
    }
}
