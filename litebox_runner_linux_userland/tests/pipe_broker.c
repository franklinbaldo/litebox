// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

struct io_thread_args {
    int fd;
    unsigned char value;
    int write;
    int result;
};

static void *io_thread(void *arg) {
    struct io_thread_args *args = arg;
    unsigned char value = args->value;
    ssize_t result = args->write ? write(args->fd, &value, 1)
                                 : read(args->fd, &value, 1);
    args->result = result == 1 && (args->write || value == args->value) ? 0 : 1;
    return NULL;
}

static int poll_events(int fd, short events, short expected) {
    struct pollfd poll_fd = {
        .fd = fd,
        .events = events,
    };
    int ready = poll(&poll_fd, 1, 0);
    return ready >= 0 && poll_fd.revents == expected ? 0 : 1;
}

static int test_nonblocking_and_lifecycle(void) {
    int fds[2];
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) {
        return 1;
    }
    if ((fcntl(fds[0], F_GETFL) & O_NONBLOCK) == 0 ||
        (fcntl(fds[1], F_GETFL) & O_NONBLOCK) == 0 ||
        (fcntl(fds[0], F_GETFD) & FD_CLOEXEC) == 0 ||
        (fcntl(fds[1], F_GETFD) & FD_CLOEXEC) == 0) {
        return 2;
    }
    if (poll_events(fds[0], POLLIN, 0) != 0 ||
        poll_events(fds[1], POLLOUT, POLLOUT) != 0) {
        return 3;
    }

    unsigned char data[3] = {1, 2, 3};
    unsigned char output[3] = {0};
    errno = 0;
    if (read(fds[0], output, sizeof(output)) != -1 || errno != EAGAIN) {
        return 4;
    }
    if (write(fds[1], data, sizeof(data)) != sizeof(data) ||
        poll_events(fds[0], POLLIN, POLLIN) != 0 ||
        read(fds[0], output, sizeof(output)) != sizeof(output) ||
        memcmp(data, output, sizeof(data)) != 0) {
        return 5;
    }

    int duplicate = dup(fds[1]);
    if (duplicate < 0 || close(fds[1]) != 0 ||
        write(duplicate, data, sizeof(data)) != sizeof(data) ||
        read(fds[0], output, sizeof(output)) != sizeof(output)) {
        return 6;
    }
    return close(duplicate) == 0 && close(fds[0]) == 0 ? 0 : 7;
}

static int test_blocking_read_wakeup(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        return 1;
    }
    struct io_thread_args args = {
        .fd = fds[0],
        .value = 42,
        .write = 0,
        .result = -1,
    };
    pthread_t thread;
    if (pthread_create(&thread, NULL, io_thread, &args) != 0) {
        return 2;
    }
    usleep(10000);
    unsigned char value = 42;
    if (write(fds[1], &value, 1) != 1 ||
        pthread_join(thread, NULL) != 0 || args.result != 0) {
        return 3;
    }

    unsigned char input[65536];
    unsigned char output[65536];
    memset(input, 0x5a, sizeof(input));
    if (write(fds[1], input, sizeof(input)) != sizeof(input)) {
        return 4;
    }
    size_t read_size = 0;
    while (read_size < sizeof(output)) {
        ssize_t size =
            read(fds[0], output + read_size, sizeof(output) - read_size);
        if (size <= 0) {
            return 5;
        }
        read_size += (size_t)size;
    }
    if (memcmp(input, output, sizeof(input)) != 0) {
        return 6;
    }
    return close(fds[0]) == 0 && close(fds[1]) == 0 ? 0 : 7;
}

static int test_blocking_write_wakeup(void) {
    int fds[2];
    if (pipe2(fds, O_NONBLOCK) != 0) {
        return 1;
    }
    unsigned char data[4096] = {0};
    while (write(fds[1], data, sizeof(data)) == sizeof(data)) {
    }
    if (errno != EAGAIN || fcntl(fds[1], F_SETFL, 0) != 0) {
        return 2;
    }

    struct io_thread_args args = {
        .fd = fds[1],
        .value = 7,
        .write = 1,
        .result = -1,
    };
    pthread_t thread;
    if (pthread_create(&thread, NULL, io_thread, &args) != 0) {
        return 3;
    }
    usleep(10000);
    unsigned char value;
    if (read(fds[0], &value, 1) != 1 ||
        pthread_join(thread, NULL) != 0 || args.result != 0) {
        return 4;
    }
    return close(fds[0]) == 0 && close(fds[1]) == 0 ? 0 : 5;
}

static int test_closed_peers(void) {
    int fds[2];
    unsigned char value = 1;
    if (pipe(fds) != 0 || close(fds[1]) != 0 ||
        poll_events(fds[0], POLLIN, POLLHUP) != 0 ||
        read(fds[0], &value, 1) != 0 || close(fds[0]) != 0) {
        return 1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR || pipe(fds) != 0 ||
        close(fds[0]) != 0 ||
        poll_events(fds[1], POLLOUT, POLLERR) != 0) {
        return 2;
    }
    errno = 0;
    if (write(fds[1], &value, 1) != -1 || errno != EPIPE) {
        return 3;
    }
    return close(fds[1]) == 0 ? 0 : 4;
}

int main(void) {
    int result = test_nonblocking_and_lifecycle();
    if (result != 0) {
        return 10 + result;
    }
    result = test_blocking_read_wakeup();
    if (result != 0) {
        return 20 + result;
    }
    result = test_blocking_write_wakeup();
    if (result != 0) {
        return 30 + result;
    }
    result = test_closed_peers();
    return result == 0 ? 0 : 40 + result;
}
