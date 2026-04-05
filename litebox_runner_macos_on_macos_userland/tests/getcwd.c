// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <unistd.h>
#include <string.h>

int main(void) {
    char buf[256];

    // Test 1: getcwd should succeed (return non-NULL)
    if (getcwd(buf, sizeof(buf)) == (void *)0) return 1;

    // Test 2: result should be "/"
    if (strcmp(buf, "/") != 0) return 2;

    return 0;
}
