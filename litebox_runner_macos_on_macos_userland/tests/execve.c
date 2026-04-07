// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test execve behavior with self-exec:
//
// Phase 1 (no PHASE env var):
//   - execve(argv[0]) with PHASE=after_exec in envp, passing
//     a marker value "42" as argv[1].
//
// Phase 2 (PHASE=after_exec):
//   - Verify argv[1] == "42" (args survived execve).
//   - Verify PHASE env var is "after_exec" (envp survived execve).
//   - Exit 0 on success.
//
// Also tests that execve of a non-existent path fails with ENOENT
// and the original program continues.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    const char *phase = getenv("PHASE");

    if (!phase) {
        // Phase 1: test error path first, then self-exec.

        // execve of a non-existent path should fail with ENOENT.
        char *dummy_argv[] = { "nonexistent", NULL };
        char *dummy_envp[] = { NULL };
        int rc = execve("/nonexistent", dummy_argv, dummy_envp);
        if (rc != -1 || errno != ENOENT) {
            fprintf(stderr, "[FAIL] execve(/nonexistent) did not fail with ENOENT (rc=%d errno=%d)\n",
                    rc, errno);
            return 1;
        }

        // Self-exec with new args and env.
        char *new_argv[] = { argv[0], "42", NULL };
        char *new_envp[] = { "PHASE=after_exec", "PATH=/bin", NULL };
        execve(argv[0], new_argv, new_envp);

        // If we reach here, execve failed.
        perror("execve self");
        return 2;
    }

    // Phase 2: verify state after execve.
    int ok = 1;

    if (strcmp(phase, "after_exec") != 0) {
        fprintf(stderr, "[FAIL] PHASE != after_exec (got \"%s\")\n", phase);
        ok = 0;
    }

    if (argc < 2 || strcmp(argv[1], "42") != 0) {
        fprintf(stderr, "[FAIL] argv[1] != \"42\" (argc=%d, argv[1]=%s)\n",
                argc, argc >= 2 ? argv[1] : "(null)");
        ok = 0;
    }

    if (ok) {
        printf("[OK] execve self-exec succeeded: PHASE=%s argv[1]=%s\n", phase, argv[1]);
        return 0;
    }
    return 1;
}
