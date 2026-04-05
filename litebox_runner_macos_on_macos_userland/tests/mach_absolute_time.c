// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <mach/mach_time.h>

int main(void) {
    // Test 1: first call should return nonzero
    uint64_t t1 = mach_absolute_time();
    if (t1 == 0) return 1;

    // Burn some time so t2 > t1
    volatile int x = 0;
    for (int i = 0; i < 100000; i++) {
        x += i;
    }

    // Test 2: second call should also be nonzero
    uint64_t t2 = mach_absolute_time();
    if (t2 == 0) return 2;

    // Test 3: monotonic — t2 >= t1
    if (t2 < t1) return 3;

    return 0;
}
