/* Test fixture only: Linux syscalls over dedicated guest descriptors. */
#include <unistd.h>
#include <stdint.h>
#include <string.h>

static int exact(int fd, unsigned char *p, size_t n) {
    while (n) { ssize_t k = read(fd, p, n); if (k <= 0) return -1; p += k; n -= k; }
    return 0;
}
static int fragmented(int fd, const unsigned char *p, size_t n) {
    while (n--) { if (write(fd, p++, 1) != 1) return -1; }
    return 0;
}
int main(void) {
    unsigned char hello[12], header[4], body[1024];
    if (exact(3, hello, 12) || memcmp(hello, "LBDF", 4)) return 10;
    if (fragmented(4, hello, 12) || exact(3, header, 4)) return 11;
    uint32_t n = (uint32_t)header[0] | (uint32_t)header[1]<<8 |
                 (uint32_t)header[2]<<16 | (uint32_t)header[3]<<24;
    if (n > sizeof(body) || exact(3, body, n)) return 12;
    if (fragmented(4, header, 4) || fragmented(4, body, n)) return 13;
    if (close(4)) return 14;
    /* Host closes its input writer after receiving EOF. */
    if (read(3, body, 1) != 0) return 15;
    close(3);
    return write(1, "GUEST_STDOUT_OK\n", 16) == 16 ? 0 : 16;
}
