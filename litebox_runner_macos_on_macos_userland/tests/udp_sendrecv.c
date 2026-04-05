// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: UDP send/recv — two sockets, sendto/recvfrom with address verification.
// Single-process: receiver binds to 127.0.0.1:0, sender uses sendto(),
// receiver uses recvfrom() and verifies data + source address.
// Exit codes: 0 = success, 1-10 = specific failure step.

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    // Create receiver socket
    int rfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rfd < 0) _exit(1);

    // Bind receiver to 127.0.0.1:0
    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_len = sizeof(recv_addr);
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = 0;
    recv_addr.sin_addr.s_addr = htonl(0x7f000001);

    if (bind(rfd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) != 0) _exit(2);

    // Discover assigned port
    struct sockaddr_in bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (getsockname(rfd, (struct sockaddr *)&bound_addr, &bound_len) != 0) _exit(3);

    // Create sender socket
    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) _exit(4);

    // Send data to receiver
    const char *msg = "hello udp";
    ssize_t msg_len = (ssize_t)strlen(msg);
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_len = sizeof(dest_addr);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = bound_addr.sin_port; // already in network order
    dest_addr.sin_addr.s_addr = htonl(0x7f000001);

    ssize_t sent = sendto(sfd, msg, (size_t)msg_len, 0,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent != msg_len) _exit(5);

    // Receive data
    char buf[128];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(rfd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from_addr, &from_len);
    if (n != msg_len) _exit(6);
    if (memcmp(buf, msg, (size_t)n) != 0) _exit(7);

    // Verify source address is 127.0.0.1
    if (from_addr.sin_addr.s_addr != htonl(0x7f000001)) _exit(8);

    close(sfd);
    close(rfd);

    _exit(0);
}
