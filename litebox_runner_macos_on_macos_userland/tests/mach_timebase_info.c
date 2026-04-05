// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <mach/mach_time.h>

int main(void) {
    mach_timebase_info_data_t info;

    // Test 1: mach_timebase_info should succeed (return KERN_SUCCESS = 0)
    kern_return_t kr = mach_timebase_info(&info);
    if (kr != 0) return 1;

    // Test 2: numer should be non-zero
    // (the actual value is hardware-dependent; on some Apple Silicon it's 1,
    //  on others it's 125)
    if (info.numer == 0) return 2;

    // Test 3: denom should be non-zero
    if (info.denom == 0) return 3;

    return 0;
}
