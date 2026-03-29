/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    printf("Before fork\n");

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* child */
        printf("Hello from dynamic fork child! pid=%d\n", getpid());
        return 0;
    }

    /* parent */
    int status;
    waitpid(pid, &status, 0);
    printf("Hello from dynamic fork parent! child exited with %d\n",
           WEXITSTATUS(status));
    return 0;
}
