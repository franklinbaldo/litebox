// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <mach/mach_time.h>

int main(void) {
    mach_timebase_info_data_t info;

    // Test 1: mach_timebase_info should succeed (return KERN_SUCCESS = 0)
    kern_return_t kr = mach_timebase_info(&info);
    if (kr != 0) return 1;

    // Test 2: on Apple Silicon, numer should be 1
    if (info.numer != 1) return 2;

    // Test 3: on Apple Silicon, denom should be 1
    if (info.denom != 1) return 3;

    return 0;
}
