// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Helper: block forever until killed by a signal.

#include <unistd.h>

int main(void) {
    pause();
    return 0;
}
