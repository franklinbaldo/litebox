// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Multithreaded RR test: spawn threads, shared atomic counter, join.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>

#define NUM_THREADS 2
#define ITERS_PER_THREAD 1000

static atomic_int counter = 0;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        atomic_fetch_add(&counter, 1);
    }
    return NULL;
}

int main(void) {
    printf("Starting threads RR test...\n");

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        int rc = pthread_create(&threads[i], NULL, worker, NULL);
        if (rc != 0) {
            fprintf(stderr, "FAIL: pthread_create returned %d\n", rc);
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    int final_val = atomic_load(&counter);
    if (final_val != NUM_THREADS * ITERS_PER_THREAD) {
        fprintf(stderr, "FAIL: counter=%d, expected %d\n",
                final_val, NUM_THREADS * ITERS_PER_THREAD);
        return 1;
    }

    printf("threads_rr: PASS (counter=%d)\n", final_val);
    return 0;
}
