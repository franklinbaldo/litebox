// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The Linux AArch64 syscall ABI preserves every general-purpose register across
// an `SVC` except `x0` (the return value). In particular it preserves `x16` and
// `x17` (IP0/IP1): `svc` is *not* a function call, so the AAPCS allowance that
// lets a linker-inserted veneer clobber IP0/IP1 does not apply. glibc's
// `INTERNAL_SYSCALL` clobbers only `"memory"`, so a compiler may legitimately
// keep a live value in `x16`/`x17` across an inlined `svc`.
//
// LiteBox's AArch64 rewriter replaces the `svc` with a branch into a gate that
// spills `x16` and re-enters the runtime; a runtime that fails to restore
// `x16` corrupts guest state *silently*, with no fault. This test pins the
// contract end to end.

#include "helpers.h"

#ifdef __aarch64__

#define SENTINEL_X16 12345L
#define SENTINEL_X17 54321L

// `write(1, "", 0)` — a real syscall with no observable side effect, issued
// with a sentinel live in `x16` across the `svc`.
static long probe_x16(void) {
    register long x8 asm("x8") = __NR_write;
    register long x0 asm("x0") = 1;
    register long x1 asm("x1") = (long)"";
    register long x2 asm("x2") = 0;
    register long x16 asm("x16") = SENTINEL_X16;

    asm volatile("svc #0"
                 : "+r"(x0), "+r"(x16)
                 : "r"(x8), "r"(x1), "r"(x2)
                 : "memory");

    TEST_ASSERT(x0 == 0, "write(1, \"\", 0) should return 0");
    return x16;
}

// Same, for `x17`. The gate documents that it never touches `x17`; verify that
// claim end to end rather than trusting it.
static long probe_x17(void) {
    register long x8 asm("x8") = __NR_write;
    register long x0 asm("x0") = 1;
    register long x1 asm("x1") = (long)"";
    register long x2 asm("x2") = 0;
    register long x17 asm("x17") = SENTINEL_X17;

    asm volatile("svc #0"
                 : "+r"(x0), "+r"(x17)
                 : "r"(x8), "r"(x1), "r"(x2)
                 : "memory");

    TEST_ASSERT(x0 == 0, "write(1, \"\", 0) should return 0");
    return x17;
}

int main(void) {
    long x16 = probe_x16();
    if (x16 != SENTINEL_X16) {
        fprintf(stderr, "FAIL: x16 not preserved across svc: got %ld, want %ld\n", x16,
                SENTINEL_X16);
        return 1;
    }

    long x17 = probe_x17();
    if (x17 != SENTINEL_X17) {
        fprintf(stderr, "FAIL: x17 not preserved across svc: got %ld, want %ld\n", x17,
                SENTINEL_X17);
        return 1;
    }

    return 0;
}

#else // !__aarch64__

// The register contract under test is AArch64-specific; on other architectures
// this compiles to a trivially passing program so the shared C-test harness can
// still build and run it.
int main(void) {
    return 0;
}

#endif // __aarch64__
