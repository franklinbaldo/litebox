// tcp_connect_nolibc.c — minimal no-libc TCP connect test for networking
// Compile: gcc -static -nostdlib -o tcp_connect_nolibc tcp_connect_nolibc.c
//
// Attempts to:
// 1. Create a TCP socket
// 2. Connect to 10.0.0.1:80 (the TUN gateway — won't actually serve, but connect should work or ECONNREFUSED)
// 3. Report result
#include <asm/unistd.h>

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char sin_zero[8];
};

static long my_syscall1(long nr, long a1) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "0"(nr), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static long my_syscall2(long nr, long a1, long a2) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "0"(nr), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static long my_syscall3(long nr, long a1, long a2, long a3) {
    long ret;
    register long r10 __asm__("r10") = 0;
    asm volatile("syscall" : "=a"(ret) : "0"(nr), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static void write_str(const char *s) {
    int len = 0;
    while (s[len]) len++;
    long ret;
    asm volatile("syscall" : "=a"(ret) : "0"(__NR_write), "D"(1), "S"(s), "d"(len) : "rcx", "r11", "memory");
}

static void write_num(long n) {
    char buf[20];
    int neg = 0;
    if (n < 0) { neg = 1; n = -n; }
    int i = 19;
    buf[i--] = 0;
    if (n == 0) { buf[i--] = '0'; }
    while (n > 0) { buf[i--] = '0' + (n % 10); n /= 10; }
    if (neg) buf[i--] = '-';
    write_str(buf + i + 1);
}

void _start(void) {
    write_str("TCP connect test starting...\n");

    // socket(AF_INET, SOCK_STREAM, 0)
    long sockfd = my_syscall3(__NR_socket, AF_INET, SOCK_STREAM, 0);
    write_str("socket() = ");
    write_num(sockfd);
    write_str("\n");
    if (sockfd < 0) {
        write_str("FAIL: socket() failed\n");
        my_syscall1(__NR_exit_group, 1);
        __builtin_unreachable();
    }

    // connect to 10.0.0.1:80
    // 10.0.0.1 = 0x0100000A in network byte order (little endian: 0x0A000001)
    // port 80 = 0x5000 in network byte order
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0x5000;  // htons(80) = 0x0050 -> stored as 0x5000 on LE
    addr.sin_addr = 0x0100000A; // 10.0.0.1 in network byte order
    for (int i = 0; i < 8; i++) addr.sin_zero[i] = 0;

    // connect(sockfd, &addr, sizeof(addr))
    // connect is syscall 42
    long ret;
    register long r10 __asm__("r10") = 0;
    asm volatile("syscall" : "=a"(ret) : "0"((long)__NR_connect), "D"(sockfd), "S"((long)&addr), "d"((long)sizeof(addr)) : "rcx", "r11", "memory");

    write_str("connect() = ");
    write_num(ret);
    write_str("\n");

    // ECONNREFUSED (-111) is actually a success case — it means:
    // - socket() worked
    // - connect() reached the TUN gateway
    // - TCP SYN was sent and RST received
    // This proves the full network stack is working!
    if (ret == 0) {
        write_str("PASS: connect succeeded!\n");
    } else if (ret == -111) {
        write_str("PASS: connect got ECONNREFUSED — network stack is working (no server on port 80)\n");
    } else if (ret == -110) {
        write_str("PARTIAL: connect timed out — TUN may not be routing packets\n");
    } else {
        write_str("FAIL: connect returned unexpected error: ");
        write_num(ret);
        write_str("\n");
    }

    // Also try a simple sendto on a UDP socket to verify that path
    long udpfd = my_syscall3(__NR_socket, AF_INET, 2 /* SOCK_DGRAM */, 0);
    write_str("udp socket() = ");
    write_num(udpfd);
    write_str("\n");

    if (udpfd >= 0) {
        const char ping[] = "hello";
        // sendto(udpfd, ping, 5, 0, &addr, sizeof(addr))
        // sendto is syscall 44
        register long r10_val __asm__("r10") = 0;
        register long r8_val __asm__("r8") = (long)&addr;
        register long r9_val __asm__("r9") = sizeof(addr);
        long sret;
        asm volatile("syscall" : "=a"(sret) : "0"((long)__NR_sendto), "D"(udpfd), "S"((long)ping), "d"((long)5), "r"(r10_val), "r"(r8_val), "r"(r9_val) : "rcx", "r11", "memory");
        write_str("sendto() = ");
        write_num(sret);
        write_str("\n");
        if (sret == 5) {
            write_str("PASS: sendto succeeded (5 bytes sent)\n");
        } else {
            write_str("FAIL: sendto returned ");
            write_num(sret);
            write_str("\n");
        }
    }

    write_str("TCP connect test done.\n");
    my_syscall1(__NR_exit_group, 0);
    __builtin_unreachable();
}
