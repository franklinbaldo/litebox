// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    // Write data to make read end readable
    if (write(fds[1], "test", 4) != 4) return 2;

    // Create kqueue
    int kq = kqueue();
    if (kq < 0) return 3;

    // Test 1: Register EVFILT_READ on read end, wait for event
    struct kevent change;
    EV_SET(&change, fds[0], EVFILT_READ, EV_ADD, 0, 0, (void *)0);
    if (kevent(kq, &change, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 10;

    struct kevent event;
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    int ret = kevent(kq, (struct kevent *)0, 0, &event, 1, &timeout);
    if (ret != 1) return 11;
    if ((int)event.ident != fds[0]) return 12;
    if (event.filter != EVFILT_READ) return 13;

    // Remove EVFILT_READ before Test 2 so only the write interest fires
    struct kevent del_read;
    EV_SET(&del_read, fds[0], EVFILT_READ, EV_DELETE, 0, 0, (void *)0);
    if (kevent(kq, &del_read, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 14;

    // Test 2: EVFILT_WRITE on write end — pipe not full, should fire
    struct kevent change2;
    EV_SET(&change2, fds[1], EVFILT_WRITE, EV_ADD, 0, 0, (void *)0);
    if (kevent(kq, &change2, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 20;

    struct kevent event2;
    ret = kevent(kq, (struct kevent *)0, 0, &event2, 1, &timeout);
    if (ret != 1) return 21;
    if ((int)event2.ident != fds[1]) return 22;
    if (event2.filter != EVFILT_WRITE) return 23;

    // Test 3: EV_DELETE — re-add read interest, then delete it, verify no longer fires
    struct kevent re_add;
    EV_SET(&re_add, fds[0], EVFILT_READ, EV_ADD, 0, 0, (void *)0);
    if (kevent(kq, &re_add, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 29;

    struct kevent change3;
    EV_SET(&change3, fds[0], EVFILT_READ, EV_DELETE, 0, 0, (void *)0);
    if (kevent(kq, &change3, 1, (struct kevent *)0, 0, (struct timespec *)0) < 0) return 30;

    // Only write interest should remain — poll with short timeout
    struct kevent events[2];
    struct timespec short_timeout = { .tv_sec = 0, .tv_nsec = 0 };
    ret = kevent(kq, (struct kevent *)0, 0, events, 2, &short_timeout);
    // Should get 1 event (write end only, read interest was deleted)
    if (ret != 1) return 31;
    if ((int)events[0].ident != fds[1]) return 32;

    close(kq);
    close(fds[0]);
    close(fds[1]);
    return 0;
}
