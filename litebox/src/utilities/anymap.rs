// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A convenient storage of exactly one value of any given type.
//!
//! This is heavily inspired by the ideas of [the anymap crate](https://docs.rs/anymap), but is
//! essentially a re-implementation of only the necessary elements for LiteBox. The anymap crate
//! itself would require `std` which we don't want to use here.
//!
//! Whenever we want/need to make a new decision or add an interface, we are going to try our best
//! to keep things largely consistent with the anymap crate.
//!
//! Due to how we're using it within LiteBox, what we are doing is something similar to
//! `anymap::Map<dyn Any + Send + Sync>` rather than a direct `anymap::AnyMap` (which would just be
//! equivalent to `anymap::Map<dyn Any>`).

use alloc::boxed::Box;
use core::any::{Any, TypeId};
use hashbrown::HashMap;

/// Type-erased clone function stored alongside each value.
///
/// We cannot use `Box<dyn Any + Send + Sync + Clone>` because `Clone` is not
/// object-safe (its `clone` method returns `Self`). Instead we store a
/// function pointer that knows the concrete type and can clone through the
/// trait object.
type CloneFn = fn(&(dyn Any + Send + Sync)) -> Box<dyn Any + Send + Sync>;

/// A safe store of exactly one value of any type `T`.
pub(crate) struct AnyMap {
    // Invariant: the value at a particular typeid is guaranteed to be the correct type boxed up.
    storage: HashMap<TypeId, (Box<dyn Any + Send + Sync>, CloneFn)>,
}

const GUARANTEED: &str = "guaranteed correct type by invariant";

/// Create a clone function for a specific concrete type.
fn make_clone_fn<T: Any + Clone + Send + Sync>() -> CloneFn {
    |val: &(dyn Any + Send + Sync)| -> Box<dyn Any + Send + Sync> {
        let concrete = val.downcast_ref::<T>().expect(GUARANTEED);
        Box::new(concrete.clone())
    }
}

impl AnyMap {
    /// Create a new empty `AnyMap`
    pub(crate) fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    /// Insert `v`, replacing and returning the old value if one existed already.
    ///
    /// The `Clone` bound is required to capture a type-erased clone function
    /// at insertion time. Read-only accessors (`get`, `get_mut`, `remove`) do
    /// not require `Clone`.
    pub(crate) fn insert<T: Any + Clone + Send + Sync>(&mut self, v: T) -> Option<T> {
        let old = self
            .storage
            .insert(TypeId::of::<T>(), (Box::new(v), make_clone_fn::<T>()))?;
        Some(*old.0.downcast().expect(GUARANTEED))
    }

    /// Get a reference to a value of type `T` if it exists.
    pub(crate) fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        let v = &self.storage.get(&TypeId::of::<T>())?.0;
        Some(v.downcast_ref().expect(GUARANTEED))
    }

    /// Get a mutable reference to a value of type `T` if it exists.
    pub(crate) fn get_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        let v = &mut self.storage.get_mut(&TypeId::of::<T>())?.0;
        Some(v.downcast_mut().expect(GUARANTEED))
    }

    #[expect(
        dead_code,
        reason = "currently unused, but perfectly reasonable to use in future"
    )]
    /// Remove and return the value of type `T` if it exists.
    pub(crate) fn remove<T: Any + Send + Sync>(&mut self) -> Option<T> {
        let v = self.storage.remove(&TypeId::of::<T>())?.0;
        Some(*v.downcast().expect(GUARANTEED))
    }
}

impl Clone for AnyMap {
    fn clone(&self) -> Self {
        Self {
            storage: self
                .storage
                .iter()
                .map(|(&type_id, (val, clone_fn))| (type_id, (clone_fn(val.as_ref()), *clone_fn)))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::AnyMap;

    #[test]
    fn insert_and_get() {
        let mut map = AnyMap::new();
        assert!(map.insert(42u32).is_none());
        assert_eq!(map.get::<u32>(), Some(&42));
    }

    #[test]
    fn clone_produces_independent_copy() {
        let mut original = AnyMap::new();
        original.insert(10u32);
        original.insert(String::from("hello"));

        let mut cloned = original.clone();

        // Cloned values match.
        assert_eq!(cloned.get::<u32>(), Some(&10));
        assert_eq!(cloned.get::<String>().map(String::as_str), Some("hello"));

        // Mutating the clone does not affect the original.
        *cloned.get_mut::<u32>().unwrap() = 99;
        assert_eq!(original.get::<u32>(), Some(&10));
        assert_eq!(cloned.get::<u32>(), Some(&99));
    }

    #[test]
    fn cloned_map_can_be_cloned_again() {
        let mut map = AnyMap::new();
        map.insert(7u64);
        let clone1 = map.clone();
        let clone2 = clone1.clone();
        assert_eq!(clone2.get::<u64>(), Some(&7));
    }

    #[test]
    fn clone_empty_map() {
        let map = AnyMap::new();
        let cloned = map.clone();
        assert_eq!(cloned.get::<u32>(), None);
    }
}
