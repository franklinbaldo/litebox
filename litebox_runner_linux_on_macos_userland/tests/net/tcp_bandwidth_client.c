// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Native (macOS) TCP bandwidth client.
// Connects to a server, sends data for a fixed duration, then closes
// the connection. The server is expected to be time-based and will
// report its own results via its stdout.
//
// Usage: tcp_bandwidth_client <ip> <port> <duration_seconds>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#define BUF_SIZE 65536  // 64KB send buffer

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <ip> <port> <duration_seconds>\n", argv[0]);
        return 1;
    }

    // Ignore SIGPIPE so we get EPIPE from send() instead of being killed.
    signal(SIGPIPE, SIG_IGN);

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration_sec = atoi(argv[3]);

    // Use line-buffered stdout so output appears even if we exit abnormally.
    setlinebuf(stdout);

    printf("===== TCP Bandwidth Client =====\n");
    printf("Target: %s:%d, duration: %ds\n", ip, port, duration_sec);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    // Set SO_SNDTIMEO so send() returns EAGAIN periodically, allowing
    // our time check to run even when the TCP send buffer is full.
    struct timeval snd_timeout;
    snd_timeout.tv_sec = 0;
    snd_timeout.tv_usec = 200000;  // 200ms
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd_timeout, sizeof(snd_timeout)) < 0) {
        perror("setsockopt SO_SNDTIMEO");
        // Non-fatal — continue without timeout.
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP: %s\n", ip);
        close(fd);
        return 1;
    }

    printf("Connecting...\n");
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    printf("Connected.\n");

    // Fill send buffer with a pattern.
    char buf[BUF_SIZE];
    memset(buf, 'A', sizeof(buf));

    struct timespec t_start, t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    unsigned long long total_sent = 0;
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        long elapsed_sec = t_now.tv_sec - t_start.tv_sec;
        if (t_now.tv_nsec < t_start.tv_nsec) elapsed_sec--;
        if (elapsed_sec >= duration_sec) break;

        ssize_t n = send(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) continue;
            if (errno == EPIPE) {
                // Server closed connection — stop sending.
                printf("Server closed connection (EPIPE)\n");
                break;
            }
            perror("send");
            break;
        }
        total_sent += (unsigned long long)n;
    }

    // Just close — no shutdown() needed since the server is time-based.
    close(fd);

    clock_gettime(CLOCK_MONOTONIC, &t_now);
    long long elapsed_ms = (t_now.tv_sec - t_start.tv_sec) * 1000LL
                         + (t_now.tv_nsec - t_start.tv_nsec) / 1000000LL;

    printf("Client sent %llu bytes in %lld ms", total_sent, elapsed_ms);
    if (elapsed_ms > 0) {
        double mbps = (double)total_sent / 1024.0 / 1024.0
                    / ((double)elapsed_ms / 1000.0);
        printf(" (%.2f MB/s)", mbps);
    }
    printf("\n");

    printf("===== Bandwidth Test Complete =====\n");
    return 0;
}
