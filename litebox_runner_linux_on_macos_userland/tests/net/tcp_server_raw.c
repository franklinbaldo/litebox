// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Minimal aarch64 Linux TCP echo server using raw syscalls.
// No libc dependency — suitable for static linking at any base address.
//
// Usage: tcp_server <bind_ip> <port>
// Binds to the given IP:port, accepts one connection, reads a message,
// sends a fixed response, and exits 0.

// ---- syscall numbers (aarch64 Linux) ----
#define __NR_exit        93
#define __NR_exit_group  94
#define __NR_write       64
#define __NR_close       57
#define __NR_socket      198
#define __NR_bind        200
#define __NR_listen      201
#define __NR_accept      202
#define __NR_setsockopt  208
#define __NR_sendto      206
#define __NR_recvfrom    207

#define AF_INET  2
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SO_REUSEADDR 2

typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;
typedef long           ssize_t;
typedef unsigned long  size_t;

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

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
    // Use exit_group so all threads (including network worker) are interrupted.
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
static ssize_t sys_sendto(int fd, const void *buf, size_t len, int flags, void *addr, int addrlen) {
    return syscall6(__NR_sendto, fd, (long)buf, (long)len, flags, (long)addr, addrlen);
}

// --- string helpers ---
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

// Parse "A.B.C.D" → network-order uint32
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

// Parse decimal string → int
static int parse_int(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9') {
        n = n * 10 + (*s - '0');
        s++;
    }
    return n;
}

// --- aarch64 Linux _start: extracts argc/argv from the initial stack ---
// On entry, SP points to: [argc, argv[0], argv[1], ..., NULL, envp[0], ...]
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "ldr x0, [sp]\n"        // x0 = argc
        "add x1, sp, #8\n"      // x1 = &argv[0]
        "bl main\n"             // call main(argc, argv)
        "mov x8, #94\n"         // __NR_exit_group
        "svc #0\n"
    );
}

int main(int argc, char **argv) {
    if (argc < 3) {
        puts_fd(2, "Usage: tcp_server <ip> <port>\n");
        sys_exit(1);
    }

    const char *ip_str = argv[1];
    int port = parse_int(argv[2]);

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

    puts_fd(1, "Server: Listening...\n");

    struct sockaddr_in client_addr;
    int client_len = sizeof(client_addr);
    int conn_fd = sys_accept(server_fd, &client_addr, &client_len);
    if (conn_fd < 0) {
        puts_fd(2, "accept failed\n");
        sys_exit(1);
    }
    puts_fd(1, "Server: Client connected\n");

    char buf[1024];
    ssize_t n = sys_recvfrom(conn_fd, buf, sizeof(buf), 0, 0, 0);
    if (n > 0) {
        puts_fd(1, "Server: Received data\n");
    }

    const char *response = "Hello from TCP server!";
    sys_sendto(conn_fd, response, my_strlen(response), 0, 0, 0);
    puts_fd(1, "Server: Sent response\n");

    // Do NOT call sys_close() — litebox's close_socket() blocks on graceful
    // TCP close waiting for HUP notification that never fires.  Just exit.
    puts_fd(1, "Server: Done\n");
    sys_exit(0);
}
