// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: vfork + exec a helper program, wait for it, verify exit status.
// Uses vfork() explicitly since our fork implementation has vfork semantics.
// The child must only call execve/_exit (no library calls).

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: fork_exec_wait <exit_with_path>\n");
        return 1;
    }
    const char *helper = argv[1];

    pid_t pid = vfork();
    if (pid < 0) {
        perror("vfork");
        return 1;
    }
    if (pid == 0) {
        // Child: exec the helper with exit code 42.
        execl(helper, helper, "42", (char *)NULL);
        // If exec fails, _exit immediately.
        _exit(127);
    }
    // Parent
    int wstatus;
    pid_t waited = waitpid(pid, &wstatus, 0);
    if (waited != pid) {
        fprintf(stderr, "waitpid returned %d, expected %d\n", waited, pid);
        return 1;
    }
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 42) {
        fprintf(stderr, "unexpected exit status: 0x%x (WIFEXITED=%d, WEXITSTATUS=%d)\n",
                wstatus, WIFEXITED(wstatus), WEXITSTATUS(wstatus));
        return 1;
    }
    printf("fork_exec_wait: OK\n");
    return 0;
}
