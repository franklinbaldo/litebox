// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Helper: write "hello\n" to stdout and exit.
#include <unistd.h>

int main(void) {
    const char msg[] = "hello\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    return 0;
}
