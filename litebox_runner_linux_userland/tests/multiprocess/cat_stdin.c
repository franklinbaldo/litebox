// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Helper: read stdin and write to stdout until EOF, then exit.
#include <unistd.h>

int main(void) {
    char buf[256];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        write(STDOUT_FILENO, buf, n);
    }
    return 0;
}
