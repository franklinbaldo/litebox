// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// pipe_fork_nolibc.c — pipe + fork test binary for micro-LiteBox integration
// Compile: gcc -static -nostdlib -o pipe_fork_nolibc pipe_fork_nolibc.c
//
// Exercises pipe2 + clone (fork) together:
//   1. Creates a pipe via pipe2(pipefd, 0)
//   2. Forks via clone(SIGCHLD, 0, ...) — fork semantics
//   3. Parent closes read end, writes 0xCAFEBABE to write end, closes write end,
//      waits for child, checks exit status, prints result
//   4. Child closes write end, reads from read end, closes read end,
//      verifies value, prints result
#include <asm/unistd.h>

#define SIGCHLD 17

static long my_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static long my_read(int fd, void *buf, unsigned long count) {
    return my_syscall6(__NR_read, fd, (long)buf, count, 0, 0, 0);
}

static long my_write(int fd, const void *buf, unsigned long count) {
    return my_syscall6(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

static long my_close(int fd) {
    return my_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
}

static long my_pipe2(int *pipefd, int flags) {
    return my_syscall6(__NR_pipe2, (long)pipefd, flags, 0, 0, 0, 0);
}

static long my_clone_fork(void) {
    return my_syscall6(__NR_clone, SIGCHLD, 0, 0, 0, 0, 0);
}

static long my_wait4(long pid, int *status, int options) {
    return my_syscall6(__NR_wait4, pid, (long)status, options, 0, 0, 0);
}

static __attribute__((noreturn)) void my_exit_group(int code) {
    my_syscall6(__NR_exit_group, code, 0, 0, 0, 0, 0);
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

    // Step 2: Fork
    long pid = my_clone_fork();
    if (pid < 0) {
        write_str(2, "clone (fork) failed\n");
        my_exit_group(1);
    }

    if (pid == 0) {
        // === CHILD ===
        // Close write end
        my_close(pipefd[1]);

        // Read from read end
        unsigned long value = 0;
        ret = my_read(pipefd[0], &value, sizeof(value));
        if (ret != (long)sizeof(value)) {
            write_str(2, "child: read from pipe failed\n");
            my_exit_group(1);
        }

        // Close read end
        my_close(pipefd[0]);

        // Verify value
        if (value != 0xCAFEBABEUL) {
            write_str(2, "child: value mismatch!\n");
            my_exit_group(1);
        }

        write_str(1, "Child received correct data!\n");
        my_exit_group(0);
    } else {
        // === PARENT ===
        // Close read end
        my_close(pipefd[0]);

        // Write known value to write end
        unsigned long value = 0xCAFEBABEUL;
        ret = my_write(pipefd[1], &value, sizeof(value));
        if (ret != (long)sizeof(value)) {
            write_str(2, "parent: write to pipe failed\n");
            my_exit_group(1);
        }

        // Close write end
        my_close(pipefd[1]);

        // Wait for child
        int status = 0;
        ret = my_wait4(pid, &status, 0);
        if (ret < 0) {
            write_str(2, "parent: wait4 failed\n");
            my_exit_group(1);
        }

        // Check child exit status: WIFEXITED && WEXITSTATUS == 0
        int exited = (status & 0x7f) == 0;
        int exit_code = (status >> 8) & 0xff;

        if (!exited || exit_code != 0) {
            write_str(2, "parent: child exited abnormally\n");
            my_exit_group(1);
        }

        write_str(1, "Pipe fork test passed!\n");
        my_exit_group(0);
    }
}
