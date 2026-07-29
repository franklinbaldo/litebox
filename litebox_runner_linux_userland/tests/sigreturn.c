// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A guest signal handler must not only *run*, it must *return*: the kernel
// contract is that `rt_sigreturn` restores the full interrupted context and
// execution continues exactly where it left off, with every general-purpose
// register intact.
//
// On AArch64 that return path is entirely synthetic under LiteBox. The arm64
// kernel ignores `sa_restorer` and points `x30` at the vDSO's
// `__kernel_rt_sigreturn`; LiteBox exposes no vDSO, so it installs its own
// `rt_sigreturn` trampoline in guest address space. A trampoline that is
// mis-assembled, mis-placed, or that skips the shim would corrupt the guest
// silently or never come back at all.
//
// This test pins the whole loop: handler entered -> `rt_sigreturn` -> the
// interrupted instruction stream resumes with caller-saved registers, the
// stack pointer and the return address unchanged, and the program exits 0.

#include "helpers.h"

#include <signal.h>
#include <stdint.h>

static volatile sig_atomic_t handler_runs = 0;
static volatile sig_atomic_t handler_signo = 0;

static void handler(int signo, siginfo_t *info, void *ucontext) {
    (void)info;
    (void)ucontext;
    handler_runs++;
    handler_signo = signo;
}

static void install_handler(int signo) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(signo, &sa, NULL) == 0, "sigaction failed");
}

#ifdef __aarch64__

// Sentinels chosen to be recognisable and to not be valid small immediates.
#define SENTINEL_X9 0x0909090909090909L
#define SENTINEL_X10 0x1010101010101010L
#define SENTINEL_X19 0x1919191919191919L

static long out_x9, out_x10, out_x19, out_sp_delta;

// Send ourselves `signo` with sentinels live in caller-saved (`x9`, `x10`) and
// callee-saved (`x19`) registers across the `svc`. The signal is delivered on
// the way out of this very syscall, so the interrupted context is the
// instruction right after the `svc`.
//
// `x9`/`x10` are the interesting ones: the Linux AArch64 syscall ABI preserves
// them across an `svc`, and *nothing else* would restore them after a signal —
// only a correct `rt_sigreturn` restoring the saved `sigcontext` can.
static void raise_with_sentinels(int pid, int signo) {
    register long x8 asm("x8") = SYS_kill;
    register long x0 asm("x0") = pid;
    register long x1 asm("x1") = signo;
    register long x9 asm("x9") = SENTINEL_X9;
    register long x10 asm("x10") = SENTINEL_X10;
    register long x19 asm("x19") = SENTINEL_X19;
    long sp_before, sp_after;

    asm volatile("mov %[spb], sp\n\t"
                 "svc #0\n\t"
                 "mov %[spa], sp"
                 : "+r"(x0), "+r"(x9), "+r"(x10), "+r"(x19), [spb] "=&r"(sp_before),
                   [spa] "=&r"(sp_after)
                 : "r"(x8), "r"(x1)
                 : "memory");

    TEST_ASSERT(x0 == 0, "kill(getpid(), signo) should return 0");
    out_x9 = x9;
    out_x10 = x10;
    out_x19 = x19;
    out_sp_delta = sp_after - sp_before;
}

static void check_registers_survived(void) {
    TEST_ASSERT(out_x9 == SENTINEL_X9, "x9 clobbered across signal delivery");
    TEST_ASSERT(out_x10 == SENTINEL_X10, "x10 clobbered across signal delivery");
    TEST_ASSERT(out_x19 == SENTINEL_X19, "x19 clobbered across signal delivery");
    TEST_ASSERT(out_sp_delta == 0, "sp not restored across signal delivery");
}

#else // !__aarch64__

static void raise_with_sentinels(int pid, int signo) {
    TEST_ASSERT(kill(pid, signo) == 0, "kill failed");
}

static void check_registers_survived(void) {}

#endif // __aarch64__

int main(void) {
    int pid = (int)getpid();

    install_handler(SIGUSR1);

    // The interrupted instruction stream must resume: this counter is only
    // reachable by returning from the handler through `rt_sigreturn`.
    volatile long counter = 0;

    for (int i = 0; i < 3; i++) {
        raise_with_sentinels(pid, SIGUSR1);
        check_registers_survived();
        counter++;
    }

    TEST_ASSERT(handler_runs == 3, "handler did not run exactly three times");
    TEST_ASSERT(handler_signo == SIGUSR1, "handler saw the wrong signal number");
    TEST_ASSERT(counter == 3, "execution did not resume after the handler returned");

    // Prove the process is still fully functional after all that: a syscall
    // issued after the last `rt_sigreturn` must still work.
    TEST_ASSERT(write(1, "sigreturn ok\n", 13) == 13, "write after sigreturn failed");

    return 0;
}
