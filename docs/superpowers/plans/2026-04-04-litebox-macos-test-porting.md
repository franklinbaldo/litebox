# macOS Test Porting: efault + enhanced hello

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the two easiest Linux runner tests to the macOS runner: `efault.c` (EFAULT error propagation) and enhanced `hello.c` (envp printing + clock_gettime).

**Architecture:** Both tests are dynamically linked C programs that run through the shared cache passthrough infrastructure (`run_macho_dynamic`). No new syscall implementations are needed — `efault.c` uses `write()` which already returns EFAULT on bad pointers, and `clock_gettime` goes through libSystem's commpage (not a syscall).

**Tech Stack:** C test programs compiled with `clang -arch arm64`, Rust integration tests in `loader.rs`, existing `run_macho_dynamic` test helper.

---

### Task 1: Create macOS `efault.c` test program

**Files:**
- Create: `litebox_runner_macos_on_macos_userland/tests/efault.c`

- [ ] **Step 1: Create the efault.c test program**

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int r = write(STDOUT_FILENO, (const void *)0x10000, 1);
    if (r >= 0) {
        fprintf(stderr, "write to invalid address succeeded unexpectedly\n");
        abort();
    }
    if (errno != EFAULT) {
        perror("write");
        return 1;
    }
    printf("EFAULT test passed\n");
    return 0;
}
```

This is identical to the Linux version plus an explicit success message. The `write()` call with address `0x10000` (inside `__PAGEZERO` on macOS, which covers the first 4GB) will fail with EFAULT. The macOS shim's `sys_write` returns `EFAULT` when `to_owned_slice` returns `None` for unmapped memory, and libSystem's `write()` wrapper translates the carry-flag error return to `errno = EFAULT`.

- [ ] **Step 2: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/efault.c
git commit -m "test: add macOS efault.c test program (EFAULT error propagation)"
```

---

### Task 2: Add `test_efault` integration test

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/tests/loader.rs`

- [ ] **Step 1: Add the test_efault test function to loader.rs**

Add the following test function at the end of `loader.rs` (after `test_hello_thread`). It follows the exact same shared-cache setup pattern as `test_hello_dynamic`:

```rust
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_efault() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/efault.c", "efault");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/efault"],
        &cache_result,
        "efault",
    );
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_efault -- --nocapture`
Expected: PASS with exit code 0

- [ ] **Step 3: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/loader.rs
git commit -m "test: add test_efault integration test for macOS runner"
```

---

### Task 3: Enhance macOS `hello.c` with envp printing and clock_gettime

**Files:**
- Modify: `litebox_runner_macos_on_macos_userland/tests/hello.c`

- [ ] **Step 1: Update hello.c to match Linux version's functionality**

Replace the contents of `litebox_runner_macos_on_macos_userland/tests/hello.c` with:

```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <stdio.h>
#include <time.h>

void test_clock_gettime() {
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
        perror("clock_gettime failed for start time");
        return;
    }
    // Do some work
    for (volatile int i = 0; i < 1000000; i++);
    if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
        perror("clock_gettime failed for end time");
        return;
    }
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Elapsed time: %f seconds\n", elapsed);
}

int main(int argc, char *argv[], char *envp[]) {
    int i;
    for (i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    for (i = 0; envp[i] != NULL; i++) {
        printf("envp[%d] = %s\n", i, envp[i]);
    }

    test_clock_gettime();

    return 0;
}
```

Changes from the current macOS version:
- Added `envp` parameter to `main()` and a loop to print all environment variables.
- Added `test_clock_gettime()` function calling `clock_gettime(CLOCK_MONOTONIC)` twice and printing elapsed time. On macOS, `clock_gettime` is implemented via the commpage (not a syscall), so this tests that commpage access works.
- Added `#include <time.h>` for `clock_gettime`.
- Used `volatile` in the loop counter to prevent the compiler from optimizing it away (the Linux version's `100000000` iteration plain loop may be elided by the compiler; `volatile` ensures at least some time passes). Reduced iteration count since we only need a measurable nonzero interval.

Note: The existing `test_hello_dynamic` test already passes `envp = ["PATH=/bin"]` via `run_macho_dynamic` (line 260 of `common/mod.rs`), so envp will have at least one entry.

- [ ] **Step 2: Run the existing test_hello_dynamic to verify the enhanced hello.c still works**

Run: `cargo test -p litebox_runner_macos_on_macos_userland test_hello_dynamic -- --nocapture`
Expected: PASS with exit code 0. The output should show `argv[0]`, `argv[1]`, `argv[2]`, `envp[0] = PATH=/bin`, and an elapsed time.

- [ ] **Step 3: Commit**

```bash
git add litebox_runner_macos_on_macos_userland/tests/hello.c
git commit -m "test: enhance macOS hello.c with envp printing and clock_gettime"
```

---

### Task 4: Run full test suite and verify no regressions

**Files:**
- None (verification only)

- [ ] **Step 1: Run all macOS runner tests**

Run: `cargo test -p litebox_runner_macos_on_macos_userland -- --nocapture`
Expected: All tests pass (7 non-ignored tests: hello_nolibc_asm, hello_nolibc_c, exit_code_42, hello_dynamic, hello_thread, efault, plus shared_cache unit test).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -p litebox_runner_macos_on_macos_userland -- -D warnings`
Expected: No warnings.

- [ ] **Step 3: Run cargo fmt check**

Run: `cargo fmt -p litebox_runner_macos_on_macos_userland -- --check`
Expected: No formatting issues.
