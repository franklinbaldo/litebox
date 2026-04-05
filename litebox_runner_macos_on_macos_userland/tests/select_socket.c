// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    // Create TCP server socket
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 1;

    // Bind to loopback
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0; // let kernel assign port
    unsigned char *ip = (unsigned char *)&addr.sin_addr;
    ip[0] = 127; ip[1] = 0; ip[2] = 0; ip[3] = 1;

    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 2;
    if (listen(server, 1) < 0) return 3;

    // Get assigned port
    struct sockaddr_in bound_addr;
    unsigned int addrlen = sizeof(bound_addr);
    if (getsockname(server, (struct sockaddr *)&bound_addr, &addrlen) < 0) return 4;

    // Create client socket and connect
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) return 5;

    struct sockaddr_in connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_port = bound_addr.sin_port;
    connect_addr.sin_addr = bound_addr.sin_addr;

    if (connect(client, (struct sockaddr *)&connect_addr, sizeof(connect_addr)) < 0) return 6;

    // Accept on server side
    int accepted = accept(server, (struct sockaddr *)0, (unsigned int *)0);
    if (accepted < 0) return 7;

    // Write from client
    const char *msg = "hi";
    if (write(client, msg, 2) != 2) return 8;

    // Select on accepted fd for readability
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(accepted, &readfds);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

    int ret = select(accepted + 1, &readfds, (fd_set *)0, (fd_set *)0, &tv);
    if (ret != 1) return 10;
    if (!FD_ISSET(accepted, &readfds)) return 11;

    // Read and verify
    char buf[16];
    int n = (int)read(accepted, buf, sizeof(buf));
    if (n != 2) return 12;
    if (buf[0] != 'h' || buf[1] != 'i') return 13;

    close(accepted);
    close(client);
    close(server);
    return 0;
}
