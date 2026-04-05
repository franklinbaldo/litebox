// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/select.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    // Write to make read end readable
    const char *msg = "hello";
    if (write(fds[1], msg, 5) != 5) return 2;

    // Test 1: select on read end should report readable
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fds[0], &readfds);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

    int ret = select(fds[0] + 1, &readfds, (fd_set *)0, (fd_set *)0, &tv);
    if (ret != 1) return 10;
    if (!FD_ISSET(fds[0], &readfds)) return 11;

    // Test 2: select on write end for readability with zero timeout should return 0
    // (write end is not readable)
    fd_set readfds2;
    FD_ZERO(&readfds2);
    FD_SET(fds[1], &readfds2);
    struct timeval tv2 = { .tv_sec = 0, .tv_usec = 0 };

    ret = select(fds[1] + 1, &readfds2, (fd_set *)0, (fd_set *)0, &tv2);
    if (ret != 0) return 20;

    // Test 3: select on write end for writability should report writable
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(fds[1], &writefds);
    struct timeval tv3 = { .tv_sec = 1, .tv_usec = 0 };

    ret = select(fds[1] + 1, (fd_set *)0, &writefds, (fd_set *)0, &tv3);
    if (ret != 1) return 30;
    if (!FD_ISSET(fds[1], &writefds)) return 31;

    close(fds[0]);
    close(fds[1]);
    return 0;
}
