// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Minimal aarch64 Linux TCP bandwidth receiver using raw syscalls.
// No libc dependency — suitable for static-PIE linking.
//
// Usage: tcp_bandwidth_server <bind_ip> <port> <duration_seconds>
// Binds to the given IP:port, accepts one connection, reads data for
// the specified duration, then prints a result summary line:
//   RESULT: <total_bytes> bytes in <elapsed_ms> ms
// and exits 0.
//
// The server is time-based: it reads for <duration_seconds> seconds and
// then reports, regardless of whether the client closed the connection.
// This avoids needing the `shutdown` syscall (not implemented in litebox).

// ---- syscall numbers (aarch64 Linux) ----
#define __NR_exit           93
#define __NR_exit_group     94
#define __NR_write          64
#define __NR_close          57
#define __NR_socket         198
#define __NR_bind           200
#define __NR_listen         201
#define __NR_accept         202
#define __NR_setsockopt     208
#define __NR_recvfrom       207
#define __NR_clock_gettime  113

#define AF_INET       2
#define SOCK_STREAM   1
#define SOL_SOCKET    1
#define SO_REUSEADDR  2
#define SO_RCVTIMEO   20
#define CLOCK_MONOTONIC 1

// Error numbers (returned as -errno from syscalls)
#define EAGAIN      11
#define EWOULDBLOCK EAGAIN
#define EINTR        4
#define ECONNRESET  104

typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;
typedef long           ssize_t;
typedef unsigned long  size_t;
typedef long           int64_t;
typedef unsigned long  uint64_t;

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

struct timespec {
    int64_t tv_sec;
    long    tv_nsec;
};

struct timeval {
    long tv_sec;
    long tv_usec;
};

// ---- syscall wrappers ----
static inline long syscall1(long nr, long a0) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}
static inline long syscall2(long nr, long a0, long a1) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
    return x0;
}
static inline long syscall3(long nr, long a0, long a1, long a2) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static inline long syscall5(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory");
    return x0;
}
static inline long syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}

static void sys_exit(int code) {
    // Use exit_group (not exit) so that all threads are interrupted.
    // litebox's exit_group() calls interrupt() on all threads, which wakes up
    // any blocked operations (like the network worker thread waiting on the
    // TUN fd). Plain exit() only sets is_exiting on the current thread and
    // does NOT interrupt others, causing the runner process to hang.
    syscall1(__NR_exit_group, code);
    __builtin_unreachable();
}
static ssize_t sys_write(int fd, const void *buf, size_t len) {
    return syscall3(__NR_write, fd, (long)buf, (long)len);
}
static int sys_close(int fd) {
    return (int)syscall1(__NR_close, fd);
}
static int sys_socket(int domain, int type, int protocol) {
    return (int)syscall3(__NR_socket, domain, type, protocol);
}
static int sys_bind(int fd, const struct sockaddr_in *addr, int addrlen) {
    return (int)syscall3(__NR_bind, fd, (long)addr, addrlen);
}
static int sys_listen(int fd, int backlog) {
    return (int)syscall2(__NR_listen, fd, backlog);
}
static int sys_accept(int fd, struct sockaddr_in *addr, int *addrlen) {
    return (int)syscall3(__NR_accept, fd, (long)addr, (long)addrlen);
}
static int sys_setsockopt(int fd, int level, int optname, const void *optval, int optlen) {
    return (int)syscall5(__NR_setsockopt, fd, level, optname, (long)optval, optlen);
}
static ssize_t sys_recvfrom(int fd, void *buf, size_t len, int flags, void *addr, void *addrlen) {
    return syscall6(__NR_recvfrom, fd, (long)buf, (long)len, flags, (long)addr, (long)addrlen);
}
static int sys_clock_gettime(int clockid, struct timespec *tp) {
    return (int)syscall2(__NR_clock_gettime, clockid, (long)tp);
}

// ---- helpers ----
static size_t my_strlen(const char *s) {
    size_t n = 0;
    while (*s++) n++;
    return n;
}

static void puts_fd(int fd, const char *s) {
    sys_write(fd, s, my_strlen(s));
}

static uint16_t htons(uint16_t h) {
    return (uint16_t)((h >> 8) | (h << 8));
}

static uint32_t parse_ipv4(const char *s) {
    uint32_t out = 0;
    for (int i = 0; i < 4; i++) {
        unsigned octet = 0;
        while (*s >= '0' && *s <= '9') {
            octet = octet * 10 + (unsigned)(*s - '0');
            s++;
        }
        out |= (octet & 0xFF) << (i * 8);
        if (*s == '.') s++;
    }
    return out;
}

static int parse_int(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9') {
        n = n * 10 + (*s - '0');
        s++;
    }
    return n;
}

// Convert uint64 to decimal string, returns pointer into buf (not necessarily buf[0]).
static char *u64_to_str(uint64_t val, char *buf, int buflen) {
    char *p = buf + buflen - 1;
    *p = '\0';
    if (val == 0) {
        *(--p) = '0';
        return p;
    }
    while (val > 0 && p > buf) {
        *(--p) = '0' + (char)(val % 10);
        val /= 10;
    }
    return p;
}

static int64_t elapsed_ms(struct timespec *start, struct timespec *end) {
    int64_t sec_diff = end->tv_sec - start->tv_sec;
    long nsec_diff = end->tv_nsec - start->tv_nsec;
    return sec_diff * 1000 + nsec_diff / 1000000;
}

static int64_t elapsed_sec(struct timespec *start, struct timespec *end) {
    int64_t sec = end->tv_sec - start->tv_sec;
    if (end->tv_nsec < start->tv_nsec) sec--;
    return sec;
}

// ---- entry point ----
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "ldr x0, [sp]\n"
        "add x1, sp, #8\n"
        "bl main\n"
        "mov x8, #94\n"   // exit_group, not exit (93)
        "svc #0\n"
    );
}

int main(int argc, char **argv) {
    if (argc < 4) {
        puts_fd(2, "Usage: tcp_bandwidth_server <ip> <port> <duration_seconds>\n");
        sys_exit(1);
    }

    const char *ip_str = argv[1];
    int port = parse_int(argv[2]);
    int duration = parse_int(argv[3]);

    int server_fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        puts_fd(2, "socket failed\n");
        sys_exit(1);
    }

    int one = 1;
    sys_setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    for (int i = 0; i < (int)sizeof(addr); i++) ((char *)&addr)[i] = 0;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr = parse_ipv4(ip_str);

    if (sys_bind(server_fd, &addr, sizeof(addr)) < 0) {
        puts_fd(2, "bind failed\n");
        sys_exit(1);
    }
    if (sys_listen(server_fd, 5) < 0) {
        puts_fd(2, "listen failed\n");
        sys_exit(1);
    }

    puts_fd(1, "BandwidthServer: Listening...\n");

    struct sockaddr_in client_addr;
    int client_len = sizeof(client_addr);
    int conn_fd = sys_accept(server_fd, &client_addr, &client_len);
    if (conn_fd < 0) {
        puts_fd(2, "accept failed\n");
        sys_exit(1);
    }
    puts_fd(1, "BandwidthServer: Client connected\n");

    // Set a receive timeout so recvfrom doesn't block forever.
    // This lets us check the elapsed time periodically even if no data arrives
    // (e.g., if the client disconnects and the notification doesn't wake us).
    struct timeval recv_timeout;
    recv_timeout.tv_sec = 0;
    recv_timeout.tv_usec = 500000;  // 500ms
    sys_setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));

    // Read data for the specified duration, measuring throughput.
    struct timespec t_start, t_now;
    sys_clock_gettime(CLOCK_MONOTONIC, &t_start);

    char buf[65536];  // 64KB receive buffer
    uint64_t total_bytes = 0;
    for (;;) {
        ssize_t n = sys_recvfrom(conn_fd, buf, sizeof(buf), 0, 0, 0);
        if (n > 0) {
            total_bytes += (uint64_t)n;
        } else if (n == 0) {
            // Client closed connection (FIN received).
            break;
        } else {
            // Error — negative return value.
            long err = -n;
            if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
                // Timeout or interrupt — check clock and continue.
            } else {
                // Connection reset or other error — stop.
                break;
            }
        }

        // Check if duration has elapsed.
        sys_clock_gettime(CLOCK_MONOTONIC, &t_now);
        if (elapsed_sec(&t_start, &t_now) >= duration) break;
    }

    sys_clock_gettime(CLOCK_MONOTONIC, &t_now);
    int64_t ms = elapsed_ms(&t_start, &t_now);

    // Format and print result: "RESULT: <bytes> bytes in <ms> ms\n"
    char numbuf[32];
    puts_fd(1, "RESULT: ");
    puts_fd(1, u64_to_str(total_bytes, numbuf, sizeof(numbuf)));
    puts_fd(1, " bytes in ");
    puts_fd(1, u64_to_str((uint64_t)(ms > 0 ? ms : 1), numbuf, sizeof(numbuf)));
    puts_fd(1, " ms\n");

    // Do NOT call sys_close(conn_fd) or sys_close(server_fd) here.
    // litebox's close_socket() performs a graceful TCP close that blocks
    // waiting for HUP notification, which never fires due to a known issue
    // (set_state(Closed) doesn't notify observers). Just exit directly —
    // the process termination will clean up all fds.
    puts_fd(1, "BandwidthServer: Done\n");
    sys_exit(0);
}
