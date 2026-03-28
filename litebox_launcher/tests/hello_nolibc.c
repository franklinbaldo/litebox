// hello_nolibc.c — minimal no-libc test binary for micro-LiteBox integration
// Compile: gcc -static -nostdlib -o hello_nolibc hello_nolibc.c
#include <asm/unistd.h>

void _start(void) {
    const char msg[] = "Hello from micro-LiteBox!\n";
    // write(1, msg, sizeof(msg)-1)
    long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(__NR_write), "D"(1), "S"(msg), "d"(sizeof(msg)-1)
        : "rcx", "r11", "memory"
    );
    // exit_group(0)
    asm volatile(
        "syscall"
        :
        : "a"(__NR_exit_group), "D"(0)
        : "rcx", "r11", "memory"
    );
    __builtin_unreachable();
}
