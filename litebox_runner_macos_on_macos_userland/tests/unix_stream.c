// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: AF_UNIX stream — server thread accepts a connection, echoes data back.
// Uses threads: server binds to /tmp/litebox_test.sock, client connects,
// sends "hello unix", verifies echoed data.
// Exit codes: 0 = success, 1-20 = specific failure step.

#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#define SOCK_PATH "/tmp/litebox_test.sock"

static volatile int g_server_ready = 0;

static void *server_thread(void *arg) {
    (void)arg;

    // Create server socket
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) _exit(1);

    // Remove any stale socket file
    unlink(SOCK_PATH);

    // Bind to path
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_len = sizeof(addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) _exit(2);
    if (listen(sfd, 5) != 0) _exit(3);

    // Signal client
    g_server_ready = 1;

    // Accept one connection
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);
    int cfd = accept(sfd, (struct sockaddr *)&client_addr, &client_len);
    if (cfd < 0) _exit(4);

    // Echo: read then write back
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n <= 0) _exit(5);

    ssize_t sent = send(cfd, buf, (size_t)n, 0);
    if (sent != n) _exit(6);

    close(cfd);
    close(sfd);
    unlink(SOCK_PATH);
    return NULL;
}

int main(void) {
    pthread_t srv;
    if (pthread_create(&srv, NULL, server_thread, NULL) != 0) _exit(10);

    // Wait for server to be ready
    while (!g_server_ready) {
        usleep(1000);
    }

    // Create client socket
    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) _exit(11);

    // Connect to server
    struct sockaddr_un srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sun_len = sizeof(srv_addr);
    srv_addr.sun_family = AF_UNIX;
    strncpy(srv_addr.sun_path, SOCK_PATH, sizeof(srv_addr.sun_path) - 1);

    if (connect(cfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0) _exit(12);

    // Send data
    const char *msg = "hello unix";
    ssize_t msg_len = (ssize_t)strlen(msg);
    ssize_t sent = send(cfd, msg, (size_t)msg_len, 0);
    if (sent != msg_len) _exit(13);

    // Receive echoed data
    char buf[128];
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n != msg_len) _exit(14);
    if (memcmp(buf, msg, (size_t)n) != 0) _exit(15);

    close(cfd);

    // Wait for server thread
    pthread_join(srv, NULL);

    _exit(0);
}
