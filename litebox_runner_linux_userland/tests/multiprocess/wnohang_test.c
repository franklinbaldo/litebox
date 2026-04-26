// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: waitpid with WNOHANG — poll until child exits.

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: wnohang_test <exit_with_path>\n");
        return 1;
    }
    const char *helper = argv[1];

    pid_t pid = vfork();
    if (pid < 0) {
        perror("vfork");
        return 1;
    }
    if (pid == 0) {
        execl(helper, helper, "7", (char *)NULL);
        _exit(127);
    }

    // Poll with WNOHANG until child exits.
    int wstatus;
    int attempts = 0;
    pid_t w;
    while (1) {
        w = waitpid(pid, &wstatus, WNOHANG);
        if (w < 0) {
            perror("waitpid");
            return 1;
        }
        if (w == pid) {
            break;  // Child exited.
        }
        // w == 0 means child still running; keep polling.
        attempts++;
        if (attempts > 1000000) {
            fprintf(stderr, "child did not exit after %d polls\n", attempts);
            return 1;
        }
    }

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 7) {
        fprintf(stderr, "unexpected status: 0x%x (WIFEXITED=%d, WEXITSTATUS=%d)\n",
                wstatus, WIFEXITED(wstatus), WEXITSTATUS(wstatus));
        return 1;
    }

    printf("wnohang_test: OK\n");
    return 0;
}
