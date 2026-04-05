// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: socketpair() — create connected AF_UNIX pair, bidirectional data exchange.
// Creates a pair, writes "hello pair" to sv[0], reads from sv[1] and verifies,
// then writes "reply" to sv[1], reads from sv[0] and verifies.
// Exit codes: 0 = success, 1-10 = specific failure step.

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) _exit(1);

    // Write "hello pair" to sv[0]
    const char *msg1 = "hello pair";
    ssize_t msg1_len = (ssize_t)strlen(msg1);
    ssize_t sent = write(sv[0], msg1, (size_t)msg1_len);
    if (sent != msg1_len) _exit(2);

    // Read from sv[1]
    char buf[128];
    ssize_t n = read(sv[1], buf, sizeof(buf));
    if (n != msg1_len) _exit(3);
    if (memcmp(buf, msg1, (size_t)n) != 0) _exit(4);

    // Write "reply" to sv[1]
    const char *msg2 = "reply";
    ssize_t msg2_len = (ssize_t)strlen(msg2);
    sent = write(sv[1], msg2, (size_t)msg2_len);
    if (sent != msg2_len) _exit(5);

    // Read from sv[0]
    n = read(sv[0], buf, sizeof(buf));
    if (n != msg2_len) _exit(6);
    if (memcmp(buf, msg2, (size_t)n) != 0) _exit(7);

    close(sv[0]);
    close(sv[1]);

    _exit(0);
}
