// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// fork_nolibc.c — fork test binary for micro-LiteBox integration
// Compile: gcc -static -nostdlib -o fork_nolibc fork_nolibc.c
//
// Uses clone(SIGCHLD, 0, ...) to implement fork semantics (no CLONE_VM,
// child_stack = 0 means copy parent address space).  After fork:
//   - Child (rax=0): writes message, then exit_group(0)
//   - Parent (rax>0): waits for child via wait4, writes message, then exit_group(0)
#include <asm/unistd.h>

#define SIGCHLD 17

static const char parent_msg[] = "Hello from fork parent!\n";
static const char child_msg[]  = "Hello from fork child!\n";

static long my_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile("syscall"
        : "=a"(ret)
        : "0"(__NR_write), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory");
    return ret;
}

static __attribute__((noreturn)) void my_exit_group(int code) {
    asm volatile("syscall" : : "a"(__NR_exit_group), "D"(code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

void _start(void) {
    long pid;

    // fork via clone(SIGCHLD, 0, NULL, NULL, 0)
    // Unlike thread clone, child_stack=0 means use parent's stack (fork semantics).
    // We use the "D" constraint to place SIGCHLD directly into rdi, avoiding
    // register conflicts with the manual "mov $56, %%eax".
    asm volatile(
        "xor %%esi, %%esi\n\t"          // child_stack = 0 (fork semantics)
        "xor %%edx, %%edx\n\t"          // parent_tid = 0
        "xor %%r10d, %%r10d\n\t"        // child_tid = 0
        "xor %%r8d, %%r8d\n\t"          // tls = 0
        "syscall\n\t"
        : "=a"(pid)
        : "0"((long)__NR_clone), "D"((long)SIGCHLD)
        : "rsi", "rdx", "rcx", "r8", "r10", "r11",
          "memory", "cc"
    );

    if (pid < 0) {
        // clone failed
        my_exit_group(1);
    } else if (pid == 0) {
        // CHILD
        my_write(1, child_msg, sizeof(child_msg) - 1);
        my_exit_group(0);
    } else {
        // PARENT — wait for child to exit via wait4(pid, NULL, 0, NULL)
        long wret;
        register long r10 asm("r10") = 0;  // rusage = NULL
        asm volatile("syscall"
            : "=a"(wret)
            : "0"((long)__NR_wait4), "D"(pid), "S"(0), "d"(0), "r"(r10)
            : "rcx", "r11", "memory");
        my_write(1, parent_msg, sizeof(parent_msg) - 1);
        my_exit_group(0);
    }
}
