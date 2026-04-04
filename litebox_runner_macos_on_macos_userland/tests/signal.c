// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

static void *recover_ip;

void segv_handler(int sig, siginfo_t *info, void *ctx) {
    printf("Caught signal %d (Segmentation fault)\n", sig);
    printf("  Fault address: %p\n", info->si_addr);

    if (info->si_addr != (void *)0xdeadbeef) {
        printf("FAIL: unexpected fault address\n");
        _exit(1);
    }

    ucontext_t *uctx = (ucontext_t *)ctx;
    uctx->uc_mcontext->__ss.__pc = (uint64_t)recover_ip;
}

int main() {
    struct sigaction sa = {0};
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    recover_ip = &&after_fault;

    printf("About to trigger SIGSEGV...\n");

    volatile int *p = (volatile int *)0xdeadbeef;
    *p = 42;

after_fault:
    printf("Resumed after skipping faulting instruction.\n");
    printf("Test succeeded; continuing normal execution.\n");
    return 0;
}
