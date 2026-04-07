// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: TCP echo — server thread accepts a connection, echoes data back.
// Uses threads: server binds to 10.0.0.2:0, getsockname() to discover port,
// client connects and sends "hello tcp", verifies echoed data.
// Exit codes: 0 = success, 1-20 = specific failure step.

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

// Shared state: the port assigned by bind()
static volatile int g_port = 0;
static volatile int g_server_ready = 0;

static void *server_thread(void *arg) {
    (void)arg;

    // Create server socket
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) _exit(1);

    // Allow address reuse
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind to 10.0.0.2:0 (auto-assign port)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(0x0a000002); // 10.0.0.2

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) _exit(2);

    // Discover assigned port
    struct sockaddr_in bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (getsockname(sfd, (struct sockaddr *)&bound_addr, &bound_len) != 0) _exit(3);
    g_port = ntohs(bound_addr.sin_port);

    if (listen(sfd, 5) != 0) _exit(4);

    // Signal client
    g_server_ready = 1;

    // Accept one connection
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int cfd = accept(sfd, (struct sockaddr *)&client_addr, &client_len);
    if (cfd < 0) _exit(5);

    // Echo loop: read then write back
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n <= 0) _exit(6);

    ssize_t sent = send(cfd, buf, (size_t)n, 0);
    if (sent != n) _exit(7);

    close(cfd);
    close(sfd);
    return NULL;
}

int main(void) {
    pthread_t srv;
    if (pthread_create(&srv, NULL, server_thread, NULL) != 0) _exit(10);

    // Wait for server to be ready
    while (!g_server_ready) {
        usleep(1000); // 1ms
    }

    // Create client socket
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) _exit(11);

    // Connect to server
    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_len = sizeof(srv_addr);
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons((uint16_t)g_port);
    srv_addr.sin_addr.s_addr = htonl(0x0a000002);

    if (connect(cfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0) _exit(12);

    // Send data
    const char *msg = "hello tcp";
    ssize_t msg_len = (ssize_t)strlen(msg);
    ssize_t sent = send(cfd, msg, (size_t)msg_len, 0);
    if (sent != msg_len) _exit(13);

    // Receive echoed data
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n != msg_len) _exit(14);
    if (memcmp(buf, msg, (size_t)n) != 0) _exit(15);

    close(cfd);

    // Wait for server thread to finish
    pthread_join(srv, NULL);

    _exit(0);
}
