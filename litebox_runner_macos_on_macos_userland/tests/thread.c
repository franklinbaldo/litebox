// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define NUM_THREADS 10

void* thread_func(void* arg) {
    int thread_id = *(int*)arg;
    printf("Hello from thread %d (TID: %lu)\n", thread_id, (unsigned long)pthread_self());
    return NULL;
}

int main() {
    // No early printf — test bare buffer init under thread contention.
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        int rc = pthread_create(&threads[i], NULL, thread_func, &thread_ids[i]);
        if (rc) {
            fprintf(stderr, "Error creating thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("All threads finished!\n");
    return 0;
}
