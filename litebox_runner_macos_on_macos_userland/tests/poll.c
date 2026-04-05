// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <poll.h>
#include <unistd.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    // Write data to make read end readable
    if (write(fds[1], "data", 4) != 4) return 2;

    // Test 1: poll read end for POLLIN — should be ready
    struct pollfd pfd = { .fd = fds[0], .events = POLLIN, .revents = 0 };
    int ret = poll(&pfd, 1, 0);
    if (ret != 1) return 10;
    if (!(pfd.revents & POLLIN)) return 11;

    // Test 2: poll write end for POLLOUT — pipe not full, should be ready
    struct pollfd pfd2 = { .fd = fds[1], .events = POLLOUT, .revents = 0 };
    ret = poll(&pfd2, 1, 0);
    if (ret != 1) return 20;
    if (!(pfd2.revents & POLLOUT)) return 21;

    // Test 3: create fresh pipe, poll read end with timeout=0 — nothing to read
    int fds2[2];
    if (pipe(fds2) != 0) return 3;
    struct pollfd pfd3 = { .fd = fds2[0], .events = POLLIN, .revents = 0 };
    ret = poll(&pfd3, 1, 0);
    if (ret != 0) return 30;

    close(fds[0]);
    close(fds[1]);
    close(fds2[0]);
    close(fds2[1]);
    return 0;
}
