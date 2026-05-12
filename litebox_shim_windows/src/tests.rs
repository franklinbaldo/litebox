// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

pub(crate) fn init_platform() {
    static PLATFORM_INIT: std::sync::Once = std::sync::Once::new();
    PLATFORM_INIT.call_once(|| {
        let platform = crate::Platform::new();
        litebox_platform_multiplex::set_platform(platform);
    });
}
