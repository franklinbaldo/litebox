// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// RR-compatible mmap tests: exercises mmap address determinism during
// record-and-replay. Performs multiple anonymous mmap calls without
// MAP_FIXED, stores addresses and uses them for subsequent memory
// accesses. If replay assigns different addresses, the accesses fail.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

// Test 1: Multiple anonymous mmaps without MAP_FIXED. Store addresses and
// use them across mappings (write a pointer to mapping A into mapping B,
// then dereference it). This verifies address determinism across replays.
int test_mmap_address_determinism(void) {
    const size_t page_size = 4096;

    // Create two anonymous mappings without MAP_FIXED.
    void *map_a = mmap(NULL, page_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(map_a != MAP_FAILED, "mmap A failed");

    void *map_b = mmap(NULL, page_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(map_b != MAP_FAILED, "mmap B failed");

    // Write a magic value into map_a.
    *(unsigned long *)map_a = 0xDEADBEEFCAFEBABEUL;

    // Store a pointer to map_a's data inside map_b.
    *(void **)map_b = map_a;

    // Dereference the pointer stored in map_b to read from map_a.
    // If replay assigned a different address for map_a, this dereference
    // would either segfault or read garbage.
    void *stored_ptr = *(void **)map_b;
    unsigned long value = *(unsigned long *)stored_ptr;
    TEST_ASSERT(value == 0xDEADBEEFCAFEBABEUL,
                "cross-mapping pointer dereference returned wrong value");

    munmap(map_a, page_size);
    munmap(map_b, page_size);

    printf("mmap_address_determinism: PASS\n");
    return 0;
}

// Test 2: mmap then munmap then mmap again. The second mmap may reuse the
// freed address. Verify the new mapping is functional.
int test_mmap_after_munmap(void) {
    const size_t page_size = 4096;

    void *map1 = mmap(NULL, page_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(map1 != MAP_FAILED, "first mmap failed");

    // Write and verify
    memset(map1, 0xAB, page_size);
    TEST_ASSERT(((unsigned char *)map1)[0] == 0xAB, "write to first mapping failed");

    // Unmap
    int ret = munmap(map1, page_size);
    TEST_ASSERT(ret == 0, "munmap failed");

    // Allocate again — may or may not get the same address
    void *map2 = mmap(NULL, page_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(map2 != MAP_FAILED, "second mmap failed");

    // Zero-initialized (fresh anonymous mapping)
    memset(map2, 0xCD, page_size);
    TEST_ASSERT(((unsigned char *)map2)[0] == 0xCD, "write to second mapping failed");

    munmap(map2, page_size);

    printf("mmap_after_munmap: PASS\n");
    return 0;
}

// Test 3: Large allocation to stress the address space allocator.
int test_mmap_large_allocation(void) {
    const size_t size = 16 * 4096; // 64 KiB

    void *map = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(map != MAP_FAILED, "large mmap failed");

    // Write pattern across all pages
    memset(map, 0x55, size);

    // Verify last byte
    TEST_ASSERT(((unsigned char *)map)[size - 1] == 0x55,
                "last byte of large mapping incorrect");

    munmap(map, size);

    printf("mmap_large_allocation: PASS\n");
    return 0;
}

// Test 4: Multiple mappings with pointer chain. Create N mappings, store
// a linked list through them. Traverse the list to verify all addresses
// are correct.
int test_mmap_pointer_chain(void) {
    const size_t page_size = 4096;
    const int N = 5;
    void *maps[5];

    // Create N mappings
    for (int i = 0; i < N; i++) {
        maps[i] = mmap(NULL, page_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        TEST_ASSERT(maps[i] != MAP_FAILED, "mmap in chain failed");
    }

    // Build a linked list: maps[0] -> maps[1] -> ... -> maps[N-1] -> NULL
    for (int i = 0; i < N - 1; i++) {
        *(void **)maps[i] = maps[i + 1];
    }
    *(void **)maps[N - 1] = NULL;

    // Write a unique tag in each mapping (after the pointer)
    for (int i = 0; i < N; i++) {
        *((unsigned long *)maps[i] + 1) = (unsigned long)(0x1000 + i);
    }

    // Traverse the linked list starting from maps[0]
    void *current = maps[0];
    int count = 0;
    while (current != NULL) {
        unsigned long tag = *((unsigned long *)current + 1);
        TEST_ASSERT(tag == (unsigned long)(0x1000 + count),
                    "linked list tag mismatch — address determinism failure");
        current = *(void **)current;
        count++;
    }
    TEST_ASSERT(count == N, "linked list traversal did not visit all nodes");

    // Cleanup
    for (int i = 0; i < N; i++) {
        munmap(maps[i], page_size);
    }

    printf("mmap_pointer_chain: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting mmap RR tests...\n");

    if (test_mmap_address_determinism() != 0) return 1;
    if (test_mmap_after_munmap() != 0) return 1;
    if (test_mmap_large_allocation() != 0) return 1;
    if (test_mmap_pointer_chain() != 0) return 1;

    printf("All mmap RR tests passed!\n");
    return 0;
}
