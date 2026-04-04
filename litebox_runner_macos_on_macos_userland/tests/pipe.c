// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: pipe() syscall — create pipe, write, read, verify data, close.
// Exit codes: 0 = success, 1-4 = specific failure.

#include <unistd.h>
#include <string.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) _exit(1);

    const char *msg = "hello pipe";
    ssize_t msg_len = (ssize_t)strlen(msg);

    // Write to write-end (fds[1])
    ssize_t written = write(fds[1], msg, (size_t)msg_len);
    if (written != msg_len) _exit(2);

    // Read from read-end (fds[0])
    char buf[64];
    ssize_t nread = read(fds[0], buf, sizeof(buf));
    if (nread != msg_len) _exit(3);
    if (memcmp(buf, msg, (size_t)nread) != 0) _exit(4);

    close(fds[0]);
    close(fds[1]);

    _exit(0);
}
