use mirai_annotations::{get_model_field, precondition, set_model_field};

use crate::{LiteBox, sync::RawSyncPrimitivesProvider};

pub fn acquire_descriptor_write<Platform: RawSyncPrimitivesProvider>(litebox: &LiteBox<Platform>) {
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

pub fn release_descriptor_write<Platform: RawSyncPrimitivesProvider>(litebox: &LiteBox<Platform>) {
    set_model_field!(litebox, descriptor_write_held, 0usize);
}

pub fn require_no_descriptor_writer<Platform: RawSyncPrimitivesProvider>(
    litebox: &LiteBox<Platform>,
) {
    precondition!(
        get_model_field!(litebox, descriptor_write_held, 0usize) == 0,
        "set_tcp_option requires no live descriptor writer"
    );
}
