/* Simple SIGALRM signal handler test for micro-LiteBox.
 *
 * Verifies that:
 *  1. signal(SIGALRM, handler) installs a custom handler
 *  2. alarm(1) schedules delivery
 *  3. The handler fires and the program exits cleanly
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void handler(int sig)
{
    fprintf(stderr, "ALARM fired (sig=%d)\n", sig);
    exit(0);
}

int main(void)
{
    signal(SIGALRM, handler);
    alarm(1);
    while (1) {
        /* busy wait for SIGALRM */
    }
    /* unreachable */
    return 1;
}
