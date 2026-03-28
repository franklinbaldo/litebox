// thread_nolibc.c — multi-threaded no-libc test binary for micro-LiteBox integration
// Compile: gcc -static -nostdlib -o thread_nolibc thread_nolibc.c
//
// In the micro-LiteBox rewritten binary, clone_child_entry in micro jumps to
// the guest return address with RAX=0 but may not preserve RBP/RSP or other
// callee-saved registers.  We handle this by checking RAX immediately after
// the clone syscall in inline asm and, if we are the child, doing all work
// via raw inline syscalls using only registers (no stack access) until we
// set up a fresh stack.
#include <asm/unistd.h>

#define CLONE_VM      0x00000100
#define CLONE_FS      0x00000200
#define CLONE_FILES   0x00000400
#define CLONE_SIGHAND 0x00000800
#define CLONE_THREAD  0x00010000

#define STACK_SIZE 65536

// Static child stack - must be 16-byte aligned
static char child_stack[STACK_SIZE] __attribute__((aligned(16)));

// String constants in static storage (absolute addresses, no frame needed)
static const char main_msg[] = "Hello from main thread!\n";
static const char child_msg[] = "Hello from child thread!\n";

static long my_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile("syscall"
        : "=a"(ret)
        : "0"(__NR_write), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory");
    return ret;
}

static __attribute__((noreturn)) void my_exit(int code) {
    asm volatile("syscall" : : "a"(__NR_exit), "D"(code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static __attribute__((noreturn)) void my_exit_group(int code) {
    asm volatile("syscall" : : "a"(__NR_exit_group), "D"(code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

// Child thread work - sets up its own stack frame, no inherited state needed.
static __attribute__((noreturn, noinline, used)) void child_entry(void) {
    my_write(1, child_msg, sizeof(child_msg) - 1);
    my_exit(0);
}

void _start(void) {
    my_write(1, main_msg, sizeof(main_msg) - 1);

    unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

    // We perform the clone + child dispatch entirely in asm.
    // After the syscall returns:
    //   Parent: rax > 0, falls through to label 1.
    //   Child:  rax = 0, we write the child message using raw syscalls,
    //           then exit.
    asm volatile(
        "mov $56, %%eax\n\t"            // __NR_clone
        "mov %[flags], %%rdi\n\t"
        "lea %[stack_top], %%rsi\n\t"   // child stack top
        "xor %%edx, %%edx\n\t"          // parent_tid = 0
        "xor %%r10d, %%r10d\n\t"        // child_tid = 0
        "xor %%r8d, %%r8d\n\t"          // tls = 0
        "syscall\n\t"
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"
        // --- Child path ---
        // Write child message using raw syscall (all register-based, no stack)
        "mov $1, %%eax\n\t"             // __NR_write
        "mov $1, %%edi\n\t"             // fd = stdout
        "lea %[child_msg], %%rsi\n\t"   // buf
        "mov $25, %%edx\n\t"            // count = sizeof("Hello from child thread!\n") - 1
        "syscall\n\t"
        // Exit child thread
        "mov $60, %%eax\n\t"            // __NR_exit
        "xor %%edi, %%edi\n\t"          // code = 0
        "syscall\n\t"
        "1:\n\t"
        :
        : [flags] "r"(flags),
          [stack_top] "m"(child_stack[STACK_SIZE]),
          [child_msg] "m"(child_msg)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r10", "r11",
          "memory", "cc"
    );

    // PARENT only reaches here
    // Wait for child to finish
    for (volatile long i = 0; i < 50000000; i++) {}

    my_exit_group(0);
}
