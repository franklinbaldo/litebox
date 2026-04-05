// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/uio.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    // Write three chunks via writev
    const char *a = "hello";
    const char *b = " ";
    const char *c = "world";
    struct iovec wv[3];
    wv[0].iov_base = (void *)a;
    wv[0].iov_len = 5;
    wv[1].iov_base = (void *)b;
    wv[1].iov_len = 1;
    wv[2].iov_base = (void *)c;
    wv[2].iov_len = 5;

    ssize_t written = writev(fds[1], wv, 3);
    if (written != 11) return 2;

    // Read back via readv into two buffers
    char rbuf1[6];
    char rbuf2[5];
    struct iovec rv[2];
    rv[0].iov_base = rbuf1;
    rv[0].iov_len = 6;
    rv[1].iov_base = rbuf2;
    rv[1].iov_len = 5;

    ssize_t nread = readv(fds[0], rv, 2);
    if (nread != 11) return 3;

    // Verify contents
    if (memcmp(rbuf1, "hello ", 6) != 0) return 4;
    if (memcmp(rbuf2, "world", 5) != 0) return 5;

    close(fds[0]);
    close(fds[1]);
    return 0;
}
