// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// UnixBench "Pipe-based Context Switching" benchmark (context1).
// Adapted for litebox integration testing.
//
// Changes from the original UnixBench version:
//  - Replaced alarm()/SIGALRM with clock_gettime()-based polling because
//    signal delivery to custom handlers is not yet supported in the
//    micro-LiteBox dynamic-linking path.
//  - Removed signal(SIGPIPE, SIG_IGN) which also triggers the unsupported
//    signal path; broken-pipe is handled via write() return values instead.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>

unsigned long iter;

static void report(void)
{
	fprintf(stderr, "COUNT|%lu|1|lps\n", iter);
}

// Check every N iterations whether the deadline has passed.
#define CHECK_INTERVAL 64

static struct timespec deadline;

static void set_deadline(int seconds)
{
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += seconds;
}

static int past_deadline(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec > deadline.tv_sec) ||
	       (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec);
}

int main(int argc, char *argv[])
{
	int duration;
	unsigned long check;
	int p1[2], p2[2];
	ssize_t ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: context1 duration\n");
		exit(1);
	}

	duration = atoi(argv[1]);
	iter = 0;

	if (pipe(p1) || pipe(p2)) {
		perror("pipe create failed");
		exit(1);
	}

	set_deadline(duration);

	if (fork()) {
		/* parent */
		close(p1[0]); close(p2[1]);
		while (1) {
			if ((iter & (CHECK_INTERVAL - 1)) == 0 && past_deadline()) {
				/* Time is up. Close our write end so the child sees EOF. */
				close(p1[1]);
				/* Drain any pending reply from the child. */
				read(p2[0], (char *)&check, sizeof(check));
				close(p2[0]);
				break;
			}
			if ((ret = write(p1[1], (char *)&iter, sizeof(iter))) != sizeof(iter)) {
				if ((ret == -1) && (errno == EPIPE))
					break;
				if ((ret == -1) && (errno != 0) && (errno != EINTR))
					perror("master write failed");
				exit(1);
			}
			if ((ret = read(p2[0], (char *)&check, sizeof(check))) != sizeof(check)) {
				if (ret == 0)
					break;
				if ((ret == -1) && (errno != 0) && (errno != EINTR))
					perror("master read failed");
				exit(1);
			}
			if (check != iter) {
				fprintf(stderr, "Master sync error: expect %lu, got %lu\n", iter, check);
				exit(2);
			}
			iter++;
		}
		/* Wait for child to finish. */
		int status;
		wait(&status);
		report();
		exit(0);
	}
	else {
		/* child */
		close(p1[1]); close(p2[0]);
		while (1) {
			if ((ret = read(p1[0], (char *)&check, sizeof(check))) != sizeof(check)) {
				if (ret == 0)
					break; /* parent closed pipe — we're done */
				if ((ret == -1) && (errno != 0) && (errno != EINTR))
					perror("slave read failed");
				exit(1);
			}
			if (check != iter) {
				fprintf(stderr, "Slave sync error: expect %lu, got %lu\n", iter, check);
				exit(2);
			}
			if ((ret = write(p2[1], (char *)&iter, sizeof(iter))) != sizeof(iter)) {
				if ((ret == -1) && (errno == EPIPE))
					break;
				if ((ret == -1) && (errno != 0) && (errno != EINTR))
					perror("slave write failed");
				exit(1);
			}
			iter++;
		}
		exit(0);
	}
}
