// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code that arrives by `mmap` rather than as a pre-rewritten ELF — a JIT, or
// any executable mapping the guest builds itself — must still have its syscall
// instructions rewritten before it becomes executable. If it does not, the
// guest issues a raw syscall instruction that the host kernel services
// directly, and the shim is bypassed entirely.
//
// This fixture builds the smallest possible JIT: an anonymous `PROT_READ |
// PROT_WRITE` page holding a stub that issues `uname(2)` and returns, then
// `mprotect`s the page `PROT_READ | PROT_EXEC` and calls it.
//
// Two things are asserted, and they check different halves of the contract:
//
//  1. The syscall instruction is no longer present in the page after the
//     `mprotect`. This is the *structural* property: whatever the shim did, it
//     did something, and the instruction that would have escaped is gone.
//
//  2. `uname(2)` issued from that page reports LiteBox's `sysname`, not the
//     host kernel's. This is the *behavioural* property, and it is the one that
//     actually distinguishes "serviced by the shim" from "reached the host":
//     the host kernel reports `Linux`, and only the shim reports `LiteBox`.
//
// Assertion 1 alone would pass if the shim merely trapped the site; assertion 2
// alone would pass if the compiler inlined something unexpected. Together they
// pin the whole path.

#include "helpers.h"

#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>

// The stub is `long stub(struct utsname *)`: the pointer is already in the
// first argument register on both ABIs, so the stub only has to load the
// syscall number and issue the syscall.
typedef long (*jit_fn)(struct utsname *);

#if defined(__aarch64__)

// MOVZ X8, #__NR_uname ; SVC #0 ; RET
static const unsigned int STUB[] = {
    0xD2800008u | (160u << 5), // movz x8, #160  (__NR_uname)
    0xD4000001u,               // svc #0
    0xD65F03C0u,               // ret
};
// Byte offset of the syscall instruction within `STUB`, and the raw encoding
// that must *not* survive the shim's rewrite.
#define SYSCALL_OFFSET 4
#define SYSCALL_WIDTH 4
static const unsigned char RAW_SYSCALL[SYSCALL_WIDTH] = {0x01, 0x00, 0x00, 0xD4};

#elif defined(__x86_64__)

// mov eax, __NR_uname ; syscall ; ret
static const unsigned char STUB[] = {
    0xB8, 0x3F, 0x00, 0x00, 0x00, // mov eax, 63  (__NR_uname)
    0x0F, 0x05,                   // syscall
    0xC3,                         // ret
};
#define SYSCALL_OFFSET 5
#define SYSCALL_WIDTH 2
static const unsigned char RAW_SYSCALL[SYSCALL_WIDTH] = {0x0F, 0x05};

#else
#error "this fixture only knows how to emit a syscall stub for x86-64 and AArch64"
#endif

int main(void) {
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(page != MAP_FAILED, "mmap of the JIT page should succeed");

    memcpy(page, STUB, sizeof(STUB));

    TEST_ASSERT(mprotect(page, 4096, PROT_READ | PROT_EXEC) == 0,
                "mprotect of the JIT page to RX should succeed");

    // (1) Structural: the syscall instruction must be gone.
    const unsigned char *site = (const unsigned char *)page + SYSCALL_OFFSET;
    if (memcmp(site, RAW_SYSCALL, SYSCALL_WIDTH) == 0) {
        fprintf(stderr,
                "FAIL: the syscall instruction in the JIT page was not rewritten; a guest "
                "syscall from this page escapes to the host kernel\n");
        return 1;
    }

    // (2) Behavioural: the syscall must be serviced by the shim.
    struct utsname buf;
    memset(&buf, 0, sizeof(buf));
    jit_fn stub = (jit_fn)page;
    long rc = stub(&buf);
    if (rc != 0) {
        fprintf(stderr, "FAIL: uname() from the JIT page returned %ld\n", rc);
        return 1;
    }
    if (strcmp(buf.sysname, "LiteBox") != 0) {
        fprintf(stderr,
                "FAIL: uname() from the JIT page reported sysname \"%s\"; the shim reports "
                "\"LiteBox\", so this syscall was serviced by the host kernel\n",
                buf.sysname);
        return 1;
    }

    return 0;
}
