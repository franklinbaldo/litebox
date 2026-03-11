#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

int main() {
    long pagesize = sysconf(_SC_PAGESIZE);
    for (uintptr_t addr = 0; addr < 0x100000; addr += pagesize) {
        void *p = mmap((void *)addr, pagesize,
                       PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (p != MAP_FAILED) {
            printf("Succeeded at address: 0x%lx\n", addr);
            munmap(p, pagesize);
            break;
        } else {
            // Uncomment to see where it fails
            // printf("Failed at 0x%lx: %s\n", addr, strerror(errno));
        }
    }
    return 0;
}

