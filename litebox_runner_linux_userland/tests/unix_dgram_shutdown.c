// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void fail_errno(const char *op, int expected_errno) {
    fprintf(stderr, "FAIL: %s expected errno=%d (%s), got errno=%d (%s)\n",
            op, expected_errno, strerror(expected_errno), errno, strerror(errno));
    exit(1);
}

static void expect_sys_shutdown(int fd, int how, const char *op) {
    errno = 0;
    if (syscall(SYS_shutdown, fd, how) != 0) {
        die(op);
    }
}

static void expect_send_errno(int fd, int expected_errno, const char *op) {
    errno = 0;
    ssize_t n = send(fd, "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n != -1) {
        fprintf(stderr, "FAIL: %s expected failure, got %zd\n", op, n);
        exit(1);
    }
    if (errno != expected_errno) {
        fail_errno(op, expected_errno);
    }
}

static void expect_recv_errno(int fd, int expected_errno, const char *op) {
    char buf[32];

    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n != -1) {
        fprintf(stderr, "FAIL: %s expected failure, got %zd\n", op, n);
        exit(1);
    }
    if (errno != expected_errno) {
        fail_errno(op, expected_errno);
    }
}

static void expect_recv_eof(int fd, const char *op) {
    char buf[32];

    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
        die(op);
    }
    if (n != 0) {
        fprintf(stderr, "FAIL: %s expected EOF, got %zd\n", op, n);
        exit(1);
    }
}

static void expect_recv_string(int fd, const char *expected, const char *op) {
    char buf[64];
    size_t expected_len = strlen(expected);

    memset(buf, 0, sizeof(buf));
    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n < 0) {
        die(op);
    }
    if ((size_t)n != expected_len || memcmp(buf, expected, expected_len) != 0) {
        fprintf(stderr, "FAIL: %s expected '%s' (%zu bytes), got '%.*s' (%zd bytes)\n",
                op, expected, expected_len, (int)n, buf, n);
        exit(1);
    }
}

static void make_dgram_pair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        die("socketpair(AF_UNIX, SOCK_DGRAM)");
    }
}

static void set_recv_timeout(int fd) {
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 100000 };

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        die("setsockopt(SO_RCVTIMEO)");
    }
}

static void close_pair(int sv[2]) {
    close(sv[0]);
    close(sv[1]);
}

// SHUT_RD on a connected datagram socket: queued datagrams remain readable; once the queue
// drains, a non-blocking recv returns EAGAIN (datagram quirk) while a blocking recv returns
// EOF, and the peer's send fails with EPIPE.
static void test_shutdown_read_keeps_queued_datagram(void) {
    int sv[2];
    const char *queued = "queued-before-read-shutdown";

    make_dgram_pair(sv);
    set_recv_timeout(sv[0]);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("send queued datagram before SHUT_RD");
    }

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD)");

    expect_recv_string(sv[0], queued, "recv queued datagram after SHUT_RD");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RD");
    expect_recv_errno(sv[0], EAGAIN, "empty nonblocking recv after SHUT_RD");
    expect_recv_eof(sv[0], "empty blocking recv after SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_read_empty_blocking_recv_returns_eof(void) {
    int sv[2];

    make_dgram_pair(sv);
    set_recv_timeout(sv[0]);

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD) before recv");

    expect_recv_eof(sv[0], "blocking recv after empty SHUT_RD");
    expect_send_errno(sv[1], EPIPE, "peer send after empty SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_write_keeps_receive_side_open(void) {
    int sv[2];
    const char *inbound = "still-readable-after-write-shutdown";

    make_dgram_pair(sv);

    expect_sys_shutdown(sv[0], SHUT_WR, "shutdown(SHUT_WR)");

    expect_send_errno(sv[0], EPIPE, "local send after SHUT_WR");
    if (send(sv[1], inbound, strlen(inbound), MSG_NOSIGNAL) < 0) {
        die("peer send after SHUT_WR");
    }
    expect_recv_string(sv[0], inbound, "local recv after SHUT_WR");

    close_pair(sv);
}

static void test_shutdown_both_combines_read_and_write_rules(void) {
    int sv[2];
    const char *queued = "queued-before-rdwr-shutdown";

    make_dgram_pair(sv);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("send queued datagram before SHUT_RDWR");
    }

    expect_sys_shutdown(sv[0], SHUT_RDWR, "shutdown(SHUT_RDWR)");

    expect_send_errno(sv[0], EPIPE, "local send after SHUT_RDWR");
    expect_recv_string(sv[0], queued, "recv queued datagram after SHUT_RDWR");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RDWR");
    expect_recv_errno(sv[0], EAGAIN, "empty nonblocking recv after SHUT_RDWR");

    close_pair(sv);
}

static void test_shutdown_invalid_how_returns_einval(void) {
    int sv[2];

    make_dgram_pair(sv);

    errno = 0;
    long ret = syscall(SYS_shutdown, sv[0], 99);
    if (ret != -1) {
        fprintf(stderr, "FAIL: shutdown(invalid how) expected failure, got %ld\n", ret);
        exit(1);
    }
    if (errno != EINVAL) {
        fail_errno("shutdown(invalid how)", EINVAL);
    }

    close_pair(sv);
}

int main(void) {
    printf("== unix datagram shutdown syscall tests ==\n");

    test_shutdown_read_keeps_queued_datagram();
    test_shutdown_read_empty_blocking_recv_returns_eof();
    test_shutdown_write_keeps_receive_side_open();
    test_shutdown_both_combines_read_and_write_rules();
    test_shutdown_invalid_how_returns_einval();

    printf("All unix datagram shutdown tests passed.\n");
    return 0;
}
