// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Helper: exit with the status given as argv[1].
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    return atoi(argv[1]);
}
