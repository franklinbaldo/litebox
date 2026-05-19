// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
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

static void expect_sys_shutdown_errno(int fd, int how, int expected_errno, const char *op) {
    errno = 0;
    long ret = syscall(SYS_shutdown, fd, how);
    if (ret != -1) {
        fprintf(stderr, "FAIL: %s expected failure, got %ld\n", op, ret);
        exit(1);
    }
    if (errno != expected_errno) {
        fail_errno(op, expected_errno);
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

static void make_stream_pair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        die("socketpair(AF_UNIX, SOCK_STREAM)");
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

static void test_shutdown_read_drains_then_returns_eof(void) {
    int sv[2];
    const char *queued = "before-shut-rd";

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("peer send before SHUT_RD");
    }

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD)");

    expect_recv_string(sv[0], queued, "recv queued bytes after SHUT_RD");
    expect_recv_eof(sv[0], "blocking recv after queue drained");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_read_empty_returns_eof(void) {
    int sv[2];

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD) on empty queue");

    expect_recv_eof(sv[0], "blocking recv on empty SHUT_RD queue");
    expect_send_errno(sv[1], EPIPE, "peer send after empty SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_write_keeps_receive_side_open(void) {
    int sv[2];
    const char *inbound = "still-readable-after-write-shutdown";

    make_stream_pair(sv);

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

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    expect_sys_shutdown(sv[0], SHUT_RDWR, "shutdown(SHUT_RDWR)");

    expect_send_errno(sv[0], EPIPE, "local send after SHUT_RDWR");
    expect_recv_eof(sv[0], "blocking recv after SHUT_RDWR");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RDWR");

    close_pair(sv);
}

// shutdown() on an unconnected (Init) AF_UNIX stream socket succeeds silently on Linux —
// unlike inet sockets, unix_shutdown does not enforce ENOTCONN. Lock this in so the silent
// success path in UnixStream::shutdown stays honest.
static void test_shutdown_unconnected_succeeds(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket(AF_UNIX, SOCK_STREAM)");
    }
    expect_sys_shutdown(fd, SHUT_RDWR, "shutdown(SHUT_RDWR) on unconnected unix stream");
    close(fd);
}

// Linux records pre-connect shutdown flags on the unix_sock structure and applies them once
// the socket transitions to Connected: a `shutdown(SHUT_WR)` on a freshly-created Init socket
// must cause the post-connect `send()` to fail with EPIPE.
static void test_init_shutdown_persists_to_connected(void) {
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        die("socket(server)");
    }
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    snprintf(sa.sun_path, sizeof(sa.sun_path), "/tmp/lb_shut_init_%d", getpid());
    unlink(sa.sun_path);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("bind(server)");
    }
    if (listen(srv, 4) != 0) {
        die("listen(server)");
    }

    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c < 0) {
        die("socket(client)");
    }
    expect_sys_shutdown(c, SHUT_WR, "pre-connect shutdown(SHUT_WR)");
    if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("connect after pre-connect shutdown");
    }
    expect_send_errno(c, EPIPE, "post-connect send must observe pre-connect SHUT_WR");

    close(c);
    close(srv);
    unlink(sa.sun_path);
}

// Linux's `shutdown(SHUT_RDWR)` on a listening socket is observable two ways: a blocking
// accept returns EINVAL (not tested here to avoid pthreads), and poll reports POLLIN|POLLHUP.
// We use the poll signal to confirm the listen state changed.
static void test_listen_shutdown_signals_hup(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket(listen)");
    }
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    snprintf(sa.sun_path, sizeof(sa.sun_path), "/tmp/lb_shut_listen_%d", getpid());
    unlink(sa.sun_path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("bind(listen)");
    }
    if (listen(fd, 4) != 0) {
        die("listen()");
    }
    expect_sys_shutdown(fd, SHUT_RDWR, "shutdown(listen, SHUT_RDWR)");

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int r = poll(&pfd, 1, 100);
    if (r != 1) {
        fprintf(stderr, "FAIL: poll after listen-shutdown expected 1, got %d (errno=%d)\n",
                r, errno);
        exit(1);
    }
    if (!(pfd.revents & POLLHUP)) {
        fprintf(stderr,
                "FAIL: poll after listen-shutdown expected POLLHUP, got revents=0x%x\n",
                pfd.revents);
        exit(1);
    }

    close(fd);
    unlink(sa.sun_path);
}

// When the *peer* calls shutdown(SHUT_WR), the local recv side must drain any queued bytes
// first, then observe EOF on a subsequent recv — same behavior as a local SHUT_RD, just
// triggered from the other side. Locks in the channel-layer "peer shutdown" drain path.
static void test_peer_shutdown_write_drains_then_returns_eof(void) {
    int sv[2];
    const char *queued = "bytes-before-peer-shut-wr";

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("peer send before peer SHUT_WR");
    }
    expect_sys_shutdown(sv[1], SHUT_WR, "peer shutdown(SHUT_WR)");

    expect_recv_string(sv[0], queued, "recv queued bytes after peer SHUT_WR");
    expect_recv_eof(sv[0], "blocking recv after peer SHUT_WR queue drained");

    close_pair(sv);
}

static void test_shutdown_invalid_how_returns_einval(void) {
    int sv[2];

    make_stream_pair(sv);

    expect_sys_shutdown_errno(sv[0], 99, EINVAL, "shutdown(invalid how)");

    close_pair(sv);
}

int main(void) {
    printf("== unix stream shutdown syscall tests ==\n");

    test_shutdown_read_drains_then_returns_eof();
    test_shutdown_read_empty_returns_eof();
    test_shutdown_write_keeps_receive_side_open();
    test_shutdown_both_combines_read_and_write_rules();
    test_shutdown_unconnected_succeeds();
    test_init_shutdown_persists_to_connected();
    test_listen_shutdown_signals_hup();
    test_peer_shutdown_write_drains_then_returns_eof();
    test_shutdown_invalid_how_returns_einval();

    printf("All unix stream shutdown tests passed.\n");
    return 0;
}
