//! MIRAI's feasibility rows bind `descriptor_write_held` and `descriptor_read_count` to `&LiteBox`
//! as a proxy for the single table-level `RwLock<Platform, Descriptors<Platform>>`. This
//! deliberately distinguishes that resource from each per-entry
//! `Arc<RwLock<Platform, DescriptorEntry>>`.
//!
//! The rows consume these LiteBox-level contracts rather than the separate model annotations on
//! `RwLock::read`, `RwLock::write`, and the guard `Drop` implementations.

use mirai_annotations::{get_model_field, precondition, set_model_field};

use crate::{LiteBox, sync::RawSyncPrimitivesProvider};

pub fn acquire_descriptor_write<Platform: RawSyncPrimitivesProvider>(litebox: &LiteBox<Platform>) {
    #[cfg(not(feature = "mirai_descriptor_rekey_tripwire"))]
    {
        precondition!(
            get_model_field!(litebox, descriptor_write_held, 0usize) == 0,
            "write requires no live descriptor writer"
        );
        precondition!(
            get_model_field!(litebox, descriptor_read_count, 0usize) == 0,
            "write requires no live descriptor readers"
        );
        set_model_field!(litebox, descriptor_write_held, 1usize);
    }

    #[cfg(feature = "mirai_descriptor_rekey_tripwire")]
    {
        let lock = litebox.descriptor_lock();
        precondition!(
            get_model_field!(lock, write_held, 0usize) == 0,
            "write requires no live descriptor writer"
        );
        precondition!(
            get_model_field!(lock, read_count, 0usize) == 0,
            "write requires no live descriptor readers"
        );
        set_model_field!(lock, write_held, 1usize);
    }
}

pub fn release_descriptor_write<Platform: RawSyncPrimitivesProvider>(litebox: &LiteBox<Platform>) {
    #[cfg(not(feature = "mirai_descriptor_rekey_tripwire"))]
    set_model_field!(litebox, descriptor_write_held, 0usize);
    #[cfg(feature = "mirai_descriptor_rekey_tripwire")]
    set_model_field!(litebox.descriptor_lock(), write_held, 0usize);
}

pub fn require_no_descriptor_writer<Platform: RawSyncPrimitivesProvider>(
    litebox: &LiteBox<Platform>,
) {
    #[cfg(not(feature = "mirai_descriptor_rekey_tripwire"))]
    precondition!(
        get_model_field!(litebox, descriptor_write_held, 0usize) == 0,
        "set_tcp_option requires no live descriptor writer"
    );
    #[cfg(feature = "mirai_descriptor_rekey_tripwire")]
    precondition!(
        get_model_field!(litebox.descriptor_lock(), write_held, 0usize) == 0,
        "set_tcp_option requires no live descriptor writer"
    );
}
