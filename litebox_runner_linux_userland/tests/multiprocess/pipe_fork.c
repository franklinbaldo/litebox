// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: pipe between two forked children (simulates `echo hello | cat`).
// Uses vfork + exec so children detach and run concurrently.
//
// Child 1: dup2 pipe write end to stdout, exec "echo_hello" helper
// Child 2: dup2 pipe read end to stdin, exec "cat_stdin" helper
// Parent: close pipe ends, wait for both children.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: pipe_fork <echo_hello_path> <cat_stdin_path>\n");
        return 1;
    }
    const char *echo_path = argv[1];
    const char *cat_path = argv[2];

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return 1;
    }

    // Fork child 1: writer (echo_hello)
    pid_t writer = vfork();
    if (writer < 0) {
        perror("vfork writer");
        return 1;
    }
    if (writer == 0) {
        // Redirect stdout to pipe write end
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execl(echo_path, echo_path, (char *)NULL);
        _exit(127);
    }

    // Fork child 2: reader (cat_stdin)
    pid_t reader = vfork();
    if (reader < 0) {
        perror("vfork reader");
        return 1;
    }
    if (reader == 0) {
        // Redirect stdin to pipe read end
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execl(cat_path, cat_path, (char *)NULL);
        _exit(127);
    }

    // Parent: close both pipe ends so children get proper EOF
    close(pipefd[0]);
    close(pipefd[1]);

    // Wait for both children
    int wstatus;
    for (int i = 0; i < 2; i++) {
        pid_t w = wait(&wstatus);
        if (w < 0) {
            perror("wait");
            return 1;
        }
        if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
            fprintf(stderr, "child %d exited with status 0x%x\n", w, wstatus);
            return 1;
        }
    }

    printf("pipe_fork: OK\n");
    return 0;
}
