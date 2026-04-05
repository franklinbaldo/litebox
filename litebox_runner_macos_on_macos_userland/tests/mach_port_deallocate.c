// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <mach/mach.h>

int main(void) {
    // Test 1: deallocating a well-known port should return KERN_SUCCESS
    kern_return_t kr = mach_port_deallocate(mach_task_self(), mach_task_self());
    if (kr != KERN_SUCCESS) return 1;

    return 0;
}
