// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ShimFS;

/// Placeholder for KqueueFile — full implementation in Task 4.
pub(crate) struct KqueueFile<FS: ShimFS> {
    _marker: core::marker::PhantomData<FS>,
}
