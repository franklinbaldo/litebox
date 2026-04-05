// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/time.h>

int main(void) {
    struct timeval tv;

    // Test 1: gettimeofday should succeed (return 0)
    if (gettimeofday(&tv, (void *)0) != 0) return 1;

    // Test 2: tv_sec should be a reasonable epoch time (after 2001-09-09)
    if (tv.tv_sec < 1000000000) return 2;

    // Test 3: tv_usec should be in valid range [0, 999999]
    if (tv.tv_usec < 0 || tv.tv_usec > 999999) return 3;

    return 0;
}
