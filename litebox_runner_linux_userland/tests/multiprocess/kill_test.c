// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: vfork + exec a sleeper, kill it with SIGKILL, verify WIFSIGNALED.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: kill_test <sleeper_path>\n");
        return 1;
    }
    const char *sleeper = argv[1];

    pid_t pid = vfork();
    if (pid < 0) {
        perror("vfork");
        return 1;
    }
    if (pid == 0) {
        execl(sleeper, sleeper, (char *)NULL);
        _exit(127);
    }

    // Give the child a moment to start, then kill it.
    // (In practice the child is already running after vfork returns to parent.)
    if (kill(pid, SIGKILL) < 0) {
        perror("kill");
        return 1;
    }

    int wstatus;
    pid_t w = waitpid(pid, &wstatus, 0);
    if (w != pid) {
        fprintf(stderr, "waitpid returned %d, expected %d\n", w, pid);
        return 1;
    }
    if (!WIFSIGNALED(wstatus) || WTERMSIG(wstatus) != SIGKILL) {
        fprintf(stderr, "unexpected status: 0x%x (WIFSIGNALED=%d, WTERMSIG=%d)\n",
                wstatus, WIFSIGNALED(wstatus), WTERMSIG(wstatus));
        return 1;
    }

    printf("kill_test: OK\n");
    return 0;
}
