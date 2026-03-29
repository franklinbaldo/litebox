// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// pipe_nolibc.c — pipe test binary for micro-LiteBox integration
// Compile: gcc -static -nostdlib -o pipe_nolibc pipe_nolibc.c
//
// Exercises pipe2, write (to pipe), close, read (from pipe):
//   1. Creates a pipe via pipe2(pipefd, 0)
//   2. Writes 0xDEADBEEF (as unsigned long) to the write end
//   3. Closes the write end
//   4. Reads from the read end into a buffer
//   5. Closes the read end
//   6. Verifies the read value matches
//   7. Prints success/failure message and exits
#include <asm/unistd.h>

static long my_syscall3(long nr, long a0, long a1, long a2) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static long my_write(int fd, const void *buf, unsigned long count) {
    return my_syscall3(__NR_write, fd, (long)buf, count);
}

static long my_read(int fd, void *buf, unsigned long count) {
    return my_syscall3(__NR_read, fd, (long)buf, count);
}

static long my_close(int fd) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((long)__NR_close), "D"((long)fd)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static long my_pipe2(int *pipefd, int flags) {
    return my_syscall3(__NR_pipe2, (long)pipefd, (long)flags, 0);
}

static __attribute__((noreturn)) void my_exit_group(int code) {
    __asm__ volatile(
        "syscall"
        :
        : "a"((long)__NR_exit_group), "D"((long)code)
        : "rcx", "r11", "memory"
    );
    __builtin_unreachable();
}

static unsigned long my_strlen(const char *s) {
    unsigned long len = 0;
    while (s[len]) len++;
    return len;
}

static void write_str(int fd, const char *s) {
    my_write(fd, s, my_strlen(s));
}

void _start(void) {
    int pipefd[2];
    long ret;

    // Step 1: Create pipe
    ret = my_pipe2(pipefd, 0);
    if (ret < 0) {
        write_str(2, "pipe2 failed\n");
        my_exit_group(1);
    }

    // Step 2: Write a known value to the write end
    unsigned long value = 0xDEADBEEFUL;
    ret = my_write(pipefd[1], &value, sizeof(value));
    if (ret != (long)sizeof(value)) {
        write_str(2, "write to pipe failed\n");
        my_exit_group(1);
    }

    // Step 3: Close the write end
    ret = my_close(pipefd[1]);
    if (ret < 0) {
        write_str(2, "close write end failed\n");
        my_exit_group(1);
    }

    // Step 4: Read from the read end
    unsigned long read_value = 0;
    ret = my_read(pipefd[0], &read_value, sizeof(read_value));
    if (ret != (long)sizeof(read_value)) {
        write_str(2, "read from pipe failed\n");
        my_exit_group(1);
    }

    // Step 5: Close the read end
    ret = my_close(pipefd[0]);
    if (ret < 0) {
        write_str(2, "close read end failed\n");
        my_exit_group(1);
    }

    // Step 6: Verify the value
    if (read_value != 0xDEADBEEFUL) {
        write_str(2, "value mismatch!\n");
        my_exit_group(1);
    }

    // Step 7: Success
    write_str(1, "Pipe test passed!\n");
    my_exit_group(0);
}
