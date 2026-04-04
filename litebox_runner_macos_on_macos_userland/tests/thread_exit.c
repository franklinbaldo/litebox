// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: process-wide _exit() terminates all threads.
// Spawns threads in different states (spin, yield, sleep), then one thread
// calls _exit(0). If the process exits cleanly with code 0, all threads
// were successfully torn down.

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

static void *spin_thread(void *arg) {
    (void)arg;
    volatile int x = 0;
    while (1) { x++; }
    return NULL;
}

static void *yield_thread(void *arg) {
    (void)arg;
    while (1) { sched_yield(); }
    return NULL;
}

static void *sleep_thread(void *arg) {
    (void)arg;
    while (1) { usleep(100000); } // 100ms
    return NULL;
}

static void *exit_thread(void *arg) {
    (void)arg;
    // Brief sleep to let other threads start
    usleep(10000); // 10ms
    _exit(0);
    return NULL; // unreachable
}

int main(void) {
    pthread_t t;

    // Spawn 2 threads of each type
    pthread_create(&t, NULL, spin_thread, NULL);
    pthread_create(&t, NULL, spin_thread, NULL);
    pthread_create(&t, NULL, yield_thread, NULL);
    pthread_create(&t, NULL, yield_thread, NULL);
    pthread_create(&t, NULL, sleep_thread, NULL);
    pthread_create(&t, NULL, sleep_thread, NULL);

    // Spawn the exit thread
    pthread_create(&t, NULL, exit_thread, NULL);

    // Main thread also sleeps — exit_thread will call _exit(0)
    while (1) { usleep(100000); }

    // Should never reach here
    _exit(99);
}
