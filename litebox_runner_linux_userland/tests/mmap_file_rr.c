// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// RR test for file-backed mmap: opens a known file, mmaps it with
// MAP_PRIVATE (no MAP_ANONYMOUS), reads the mapped contents, and
// verifies correctness. During replay, the open() syscall is
// non-structural (skipped), so the fd is a phantom. The RR system
// must capture the mapped memory contents during recording and
// inject them into an anonymous mapping during replay.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg)                                       \
    do {                                                             \
        if (!(cond)) {                                               \
            fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n",  \
                    __func__, __LINE__, msg, errno);                 \
            return 1;                                                \
        }                                                            \
    } while (0)

// The test data file is placed at /out/testdata.bin by the test harness.
// It contains a known 4096-byte pattern: bytes 0x00..0xFF repeated 16 times.
#define TEST_FILE "/out/testdata.bin"
#define TEST_SIZE 4096

int main(void) {
    printf("Starting file-backed mmap RR test...\n");

    int fd = open(TEST_FILE, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open test file failed");

    void *map = mmap(NULL, TEST_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    TEST_ASSERT(map != MAP_FAILED, "file-backed mmap failed");

    // Close the fd — the mapping should remain valid.
    close(fd);

    // Verify the mapped contents match the expected pattern.
    const unsigned char *data = (const unsigned char *)map;
    for (int i = 0; i < TEST_SIZE; i++) {
        unsigned char expected = (unsigned char)(i % 256);
        if (data[i] != expected) {
            fprintf(stderr,
                    "FAIL: byte %d: expected 0x%02x, got 0x%02x\n",
                    i, expected, data[i]);
            return 1;
        }
    }

    munmap(map, TEST_SIZE);

    printf("file_backed_mmap: PASS\n");
    return 0;
}
