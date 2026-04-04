// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: filesystem operations — mkdir, open/write/read, ftruncate, unlink, rmdir.
// Exit codes: 0 = success, 1-12 = specific failure.

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(void) {
    // Test mkdir
    if (mkdir("/tmp/testdir", 0755) != 0) _exit(1);

    // Test creating a file in the directory
    int fd = open("/tmp/testdir/hello.txt", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) _exit(2);
    const char *data = "hello filesystem";
    ssize_t data_len = (ssize_t)strlen(data);
    ssize_t w = write(fd, data, (size_t)data_len);
    if (w != data_len) _exit(20);
    close(fd);

    // Test reading back
    fd = open("/tmp/testdir/hello.txt", O_RDONLY);
    if (fd < 0) _exit(3);
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n != data_len) _exit(4);
    if (memcmp(buf, data, (size_t)n) != 0) _exit(5);
    close(fd);

    // Test ftruncate
    fd = open("/tmp/testdir/hello.txt", O_WRONLY);
    if (fd < 0) _exit(6);
    if (ftruncate(fd, 5) != 0) _exit(7);
    close(fd);
    fd = open("/tmp/testdir/hello.txt", O_RDONLY);
    if (fd < 0) _exit(8);
    n = read(fd, buf, sizeof(buf));
    if (n != 5) _exit(9);
    close(fd);

    // Test unlink
    if (unlink("/tmp/testdir/hello.txt") != 0) _exit(10);

    // Test rmdir
    if (rmdir("/tmp/testdir") != 0) _exit(11);

    // Verify directory is gone — re-creating should succeed
    if (mkdir("/tmp/testdir", 0755) != 0) _exit(12);
    rmdir("/tmp/testdir"); // cleanup

    _exit(0);
}
