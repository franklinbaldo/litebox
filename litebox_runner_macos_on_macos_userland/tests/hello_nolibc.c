// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Compile: clang -arch arm64 -static -nostdlib -e __start -o hello hello.c

static int bsd_write(int fd, const void *buf, unsigned long count)
{
    register long x0 __asm__("x0") = fd;
    register const void *x1 __asm__("x1") = buf;
    register unsigned long x2 __asm__("x2") = count;
    register long x16 __asm__("x16") = 4; // SYS_write

    __asm__ volatile("svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x16)
        : "memory", "cc");

    return (int)x0;
}

_Noreturn static void bsd_exit(int status)
{
    register long x0 __asm__("x0") = status;
    register long x16 __asm__("x16") = 1; // SYS_exit

    for (;;) {
        __asm__ volatile("svc #0x80"
            :
            : "r"(x0), "r"(x16)
            : "memory", "cc");
    }
}

void _start(void)
{
    bsd_write(1, "Hello from C!\n", 14);
    bsd_exit(0);
}
