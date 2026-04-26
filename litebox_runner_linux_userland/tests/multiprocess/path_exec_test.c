// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: execve with a bare name (no '/') triggers PATH resolution in the shim.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {

    pid_t pid = vfork();
    if (pid < 0) {
        perror("vfork");
        return 1;
    }
    if (pid == 0) {
        // Bare name — no '/' — triggers PATH lookup in the shim's sys_execve.
        char *const args[] = {"exit_with", "99", NULL};
        char *const envp[] = {"PATH=/out", NULL};
        execve("exit_with", args, envp);
        _exit(127);
    }

    int wstatus;
    pid_t w = waitpid(pid, &wstatus, 0);
    if (w != pid) {
        fprintf(stderr, "waitpid returned %d, expected %d\n", w, pid);
        return 1;
    }
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 99) {
        fprintf(stderr, "unexpected status: 0x%x (WIFEXITED=%d, WEXITSTATUS=%d)\n",
                wstatus, WIFEXITED(wstatus), WEXITSTATUS(wstatus));
        return 1;
    }

    printf("path_exec_test: OK\n");
    return 0;
}
