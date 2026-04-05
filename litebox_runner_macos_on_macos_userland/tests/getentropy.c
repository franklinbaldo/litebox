// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/random.h>
#include <string.h>

int main(void) {
    unsigned char buf1[32];
    unsigned char buf2[32];
    unsigned char zero[32];
    memset(zero, 0, sizeof(zero));

    // Test 1: getentropy should succeed (return 0)
    if (getentropy(buf1, sizeof(buf1)) != 0) return 1;

    // Test 2: buffer should not be all zeros
    if (memcmp(buf1, zero, sizeof(zero)) == 0) return 2;

    // Test 3: second call should also succeed
    if (getentropy(buf2, sizeof(buf2)) != 0) return 3;

    // Test 4: second buffer should not be all zeros
    if (memcmp(buf2, zero, sizeof(zero)) == 0) return 4;

    // Test 5: two calls should produce different output (non-deterministic)
    if (memcmp(buf1, buf2, sizeof(buf1)) == 0) return 5;

    return 0;
}
