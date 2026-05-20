// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: memfd_create. Verified by host probe on kernel 6.6:
//   NULL name → EFAULT (errno 14)
//   empty name → success
//   250-char name → EINVAL (limit is 249, excluding NUL)
//   249-char name → success
//   bogus flag bit 0x80000000 → EINVAL
//   MFD_CLOEXEC → fd has FD_CLOEXEC set in F_GETFD
//
// Calls syscall(SYS_memfd_create, ...) directly to exercise the raw kernel
// surface that LiteBox intercepts.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg)                                                \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d: %s)\n",        \
                    __func__, __LINE__, msg, errno, strerror(errno));         \
            exit(1);                                                          \
        }                                                                     \
    } while (0)

static int raw_memfd_create(const char *name, unsigned int flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

static void test_basic_read_write_lseek(void) {
    int fd = raw_memfd_create("basic", 0);
    TEST_ASSERT(fd >= 0, "memfd_create basic");

    const char payload[] = "hello memfd";
    const ssize_t payload_len = (ssize_t)sizeof(payload) - 1;
    ssize_t n = write(fd, payload, payload_len);
    TEST_ASSERT(n == payload_len, "write to memfd");

    off_t pos = lseek(fd, 0, SEEK_SET);
    TEST_ASSERT(pos == 0, "lseek to 0");

    char buf[64] = {0};
    n = read(fd, buf, sizeof(buf));
    TEST_ASSERT(n == payload_len, "read back length");
    TEST_ASSERT(memcmp(buf, payload, payload_len) == 0, "read back contents");

    pos = lseek(fd, 0, SEEK_END);
    TEST_ASSERT(pos == payload_len, "lseek to end reports size");

    TEST_ASSERT(close(fd) == 0, "close memfd");
}

static void test_ftruncate(void) {
    int fd = raw_memfd_create("trunc", 0);
    TEST_ASSERT(fd >= 0, "memfd_create for ftruncate");

    TEST_ASSERT(ftruncate(fd, 1024) == 0, "ftruncate to 1024");
    off_t end = lseek(fd, 0, SEEK_END);
    TEST_ASSERT(end == 1024, "size matches ftruncate");

    TEST_ASSERT(close(fd) == 0, "close memfd");
}

static void test_cloexec_flag(void) {
    int fd = raw_memfd_create("cloexec", MFD_CLOEXEC);
    TEST_ASSERT(fd >= 0, "memfd_create MFD_CLOEXEC");
    int flags = fcntl(fd, F_GETFD);
    TEST_ASSERT(flags != -1, "fcntl F_GETFD");
    TEST_ASSERT((flags & FD_CLOEXEC) != 0, "FD_CLOEXEC observable after MFD_CLOEXEC");
    TEST_ASSERT(close(fd) == 0, "close memfd");
}

static void test_no_cloexec(void) {
    int fd = raw_memfd_create("plain", 0);
    TEST_ASSERT(fd >= 0, "memfd_create no flags");
    int flags = fcntl(fd, F_GETFD);
    TEST_ASSERT(flags != -1, "fcntl F_GETFD");
    TEST_ASSERT((flags & FD_CLOEXEC) == 0, "FD_CLOEXEC unset without MFD_CLOEXEC");
    TEST_ASSERT(close(fd) == 0, "close memfd");
}

static void test_allow_sealing_accepted(void) {
    // MFD_ALLOW_SEALING is a real flag bit; passing it must succeed and yield
    // a usable fd. LiteBox doesn't implement sealing operations themselves
    // yet, so the flag is accepted as a no-op for the create call (`fcntl
    // F_ADD_SEALS` would be the place that surfaces the missing support).
    int fd = raw_memfd_create("seal", MFD_ALLOW_SEALING);
    TEST_ASSERT(fd >= 0, "memfd_create MFD_ALLOW_SEALING accepted");
    TEST_ASSERT(write(fd, "x", 1) == 1, "write to MFD_ALLOW_SEALING fd");
    TEST_ASSERT(close(fd) == 0, "close memfd");
}

static void test_empty_name(void) {
    int fd = raw_memfd_create("", 0);
    TEST_ASSERT(fd >= 0, "empty name is accepted");
    TEST_ASSERT(close(fd) == 0, "close memfd");
}

static void test_efault_null_name(void) {
    errno = 0;
    int fd = raw_memfd_create(NULL, 0);
    TEST_ASSERT(fd == -1 && errno == EFAULT, "NULL name → EFAULT");
}

static void test_einval_bogus_flag(void) {
    errno = 0;
    int fd = raw_memfd_create("bogus", 0x80000000U);
    TEST_ASSERT(fd == -1 && errno == EINVAL, "unknown flag bit → EINVAL");
}

static void test_einval_name_too_long(void) {
    char long_name[260];
    memset(long_name, 'a', 250);
    long_name[250] = '\0';
    errno = 0;
    int fd = raw_memfd_create(long_name, 0);
    TEST_ASSERT(fd == -1 && errno == EINVAL, "250-char name → EINVAL");
}

static void test_name_at_limit(void) {
    // 249 chars (the documented limit, excluding NUL) is accepted.
    char name[256];
    memset(name, 'a', 249);
    name[249] = '\0';
    int fd = raw_memfd_create(name, 0);
    TEST_ASSERT(fd >= 0, "249-char name accepted");
    TEST_ASSERT(close(fd) == 0, "close memfd");
}

static void test_multiple_memfds_same_name(void) {
    // Different memfds with the same name must be independent (the name is
    // cosmetic only — see man page).
    int fd_a = raw_memfd_create("twin", 0);
    int fd_b = raw_memfd_create("twin", 0);
    TEST_ASSERT(fd_a >= 0 && fd_b >= 0 && fd_a != fd_b, "two memfds with same name");

    TEST_ASSERT(write(fd_a, "A", 1) == 1, "write A to first");
    TEST_ASSERT(write(fd_b, "B", 1) == 1, "write B to second");

    char buf;
    TEST_ASSERT(lseek(fd_a, 0, SEEK_SET) == 0, "rewind a");
    TEST_ASSERT(read(fd_a, &buf, 1) == 1 && buf == 'A', "first reads A");
    TEST_ASSERT(lseek(fd_b, 0, SEEK_SET) == 0, "rewind b");
    TEST_ASSERT(read(fd_b, &buf, 1) == 1 && buf == 'B', "second reads B");

    TEST_ASSERT(close(fd_a) == 0, "close a");
    TEST_ASSERT(close(fd_b) == 0, "close b");
}

int main(void) {
    printf("memfd_create tests starting...\n");
    test_basic_read_write_lseek();
    test_ftruncate();
    test_cloexec_flag();
    test_no_cloexec();
    test_allow_sealing_accepted();
    test_empty_name();
    test_efault_null_name();
    test_einval_bogus_flag();
    test_einval_name_too_long();
    test_name_at_limit();
    test_multiple_memfds_same_name();
    printf("All memfd_create tests passed.\n");
    return 0;
}
