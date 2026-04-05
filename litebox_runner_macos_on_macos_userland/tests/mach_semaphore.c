// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test Mach semaphore traps via inline assembly.
//
// We cannot use the libc semaphore_create() wrapper because it goes through
// mach_msg (MIG), which our shim does not fully emulate.  Instead we invoke
// semaphore traps directly with a synthetic port name.  The shim lazily
// creates the semaphore on first use.

#include <stdint.h>

// Mach trap numbers (x16 = negative value).
#define SEMAPHORE_SIGNAL_TRAP     (-36)
#define SEMAPHORE_SIGNAL_ALL_TRAP (-37)
#define SEMAPHORE_WAIT_TRAP       (-39)
#define SEMAPHORE_TIMEDWAIT_TRAP  (-40)

#define KERN_SUCCESS              0
#define KERN_OPERATION_TIMED_OUT  49

static int64_t sem_signal(uint32_t port) {
    register uint64_t x0 __asm__("x0") = port;
    register int64_t x16 __asm__("x16") = SEMAPHORE_SIGNAL_TRAP;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory");
    return (int64_t)x0;
}

static int64_t sem_signal_all(uint32_t port) {
    register uint64_t x0 __asm__("x0") = port;
    register int64_t x16 __asm__("x16") = SEMAPHORE_SIGNAL_ALL_TRAP;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory");
    return (int64_t)x0;
}

static int64_t sem_wait(uint32_t port) {
    register uint64_t x0 __asm__("x0") = port;
    register int64_t x16 __asm__("x16") = SEMAPHORE_WAIT_TRAP;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory");
    return (int64_t)x0;
}

static int64_t sem_timedwait(uint32_t port, uint32_t sec, uint32_t nsec) {
    register uint64_t x0 __asm__("x0") = port;
    register uint64_t x1 __asm__("x1") = sec;
    register uint64_t x2 __asm__("x2") = nsec;
    register int64_t x16 __asm__("x16") = SEMAPHORE_TIMEDWAIT_TRAP;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x16)
                     : "memory");
    return (int64_t)x0;
}

int main(void) {
    // Use a synthetic port name that the shim will lazily create.
    uint32_t port = 0xABCD;

    // Test 1: signal then wait — should not block (count goes 0 -> 1, then 1 -> 0).
    int64_t kr = sem_signal(port);
    if (kr != KERN_SUCCESS) return 1;

    kr = sem_wait(port);
    if (kr != KERN_SUCCESS) return 2;

    // Test 2: signal_all on empty semaphore — should succeed.
    kr = sem_signal_all(port);
    if (kr != KERN_SUCCESS) return 3;

    // Test 3: timedwait with very short timeout — semaphore has count 0,
    // so this should block and then time out.
    kr = sem_timedwait(port, 0, 1000); // 1 microsecond
    if (kr != KERN_OPERATION_TIMED_OUT) return 4;

    // Test 4: signal then timedwait — should succeed without timing out.
    kr = sem_signal(port);
    if (kr != KERN_SUCCESS) return 5;

    kr = sem_timedwait(port, 1, 0); // 1 second timeout (should not be reached)
    if (kr != KERN_SUCCESS) return 6;

    return 0;
}
