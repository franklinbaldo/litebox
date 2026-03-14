// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdint.h>

// The magic number used to identify the LiteBox trampoline.
// This must match `TRAMPOLINE_MAGIC` in `litebox_syscall_rewriter` and `litebox_common_linux`.
// Value 0x30584f424554494c is "LITEBOX0" in little-endian (bytes: 'L','I','T','E','B','O','X','0')
#define TRAMPOLINE_MAGIC ((uint64_t)0x30584f424554494c)

#if !defined(__x86_64__) && !defined(__aarch64__)
# error "rtld_audit.c: build target must be x86_64 or aarch64"
#endif

#ifdef __x86_64__
// Linux syscall numbers (x86_64)
#define SYS_openat 257
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_fstat 5
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_exit_group 231
#elif defined(__aarch64__)
// Linux syscall numbers (aarch64)
#define SYS_openat 56
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_lseek 62
#define SYS_newfstatat 79
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_munmap 215
#define SYS_exit_group 94
#endif
#define AT_FDCWD -100

#ifdef __x86_64__
// Maximum valid userspace address (47-bit address space)
#define MAX_USERSPACE_ADDR 0x7FFFFFFFFFFFUL
#elif defined(__aarch64__)
// Maximum valid userspace address (48-bit VA space)
#define MAX_USERSPACE_ADDR 0xFFFFFFFFFFFFUL
#endif

// Trampoline header layout: magic(8) + file_offset(8) + vaddr(8) + size(8) = 32 bytes
struct __attribute__((packed)) TrampolineHeader {
  uint64_t magic;
  uint64_t file_offset;
  uint64_t vaddr;
  uint64_t trampoline_size;
};

// Linux flags
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define SEEK_SET 0

typedef long (*syscall_stub_t)(void);
static syscall_stub_t syscall_entry = 0;
#ifdef __aarch64__
// TLS lookup table pointer from the trampoline (offset 8).
// Used by do_syscall to look up the host TLS base before calling the callback.
// On Linux, syscall_callback expects x18 = host TLS.
// On macOS, host_tls is passed via [SP+40] (x18 is unreliable on macOS).
static uint64_t tls_table_ptr = 0;
#endif
static char interp[256] = {0}; // Buffer for interpreter path

// Debug output (only enabled when DEBUG is defined at build time)
#ifdef DEBUG
#define syscall_print(str, len)                                                \
  do_syscall(SYS_write, 2, (long)(str), len, 0, 0, 0)
#else
#define syscall_print(str, len)
#endif

static long do_syscall(long num, long a1, long a2, long a3, long a4, long a5,
                       long a6) {
  if (!syscall_entry)
    return -1;

#ifdef __x86_64__
  register long rax __asm__("rax") = num;
  register long rdi __asm__("rdi") = a1;
  register long rsi __asm__("rsi") = a2;
  register long rdx __asm__("rdx") = a3;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;

  __asm__ volatile("leaq 1f(%%rip), %%rcx\n"
                   "jmp *%[entry]\n"
                   "1:\n"
                   : "+r"(rax)
                   : [entry] "r"(syscall_entry), "r"(rdi), "r"(rsi), "r"(rdx),
                     "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return rax;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = num;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  register long x4 __asm__("x4") = a5;
  register long x5 __asm__("x5") = a6;

  // The trampoline snippets normally do a TLS table lookup to find host_tls,
  // but do_syscall jumps directly to the callback. We must replicate
  // the trampoline's TLS lookup here.
  //
  // Platform-adaptive TLS table lookup:
  //
  //   On macOS (running under litebox), TPIDR_EL0 is clobbered by XNU on
  //   every kernel→userspace transition, so TLS table entries are keyed by
  //   TPIDRRO_EL0 — the pthread TSD base (stable, read-only, never clobbered).
  //   TPIDRRO_EL0 is always non-zero on macOS (valid userspace pointer).
  //
  //   On Linux, TPIDRRO_EL0 is typically zero (unused by the kernel), and
  //   TLS table entries are keyed by guest_tpidr (TPIDR_EL0).
  //
  //   Detection: read TPIDRRO_EL0. If non-zero → use it as key (macOS path).
  //   If zero → use TPIDR_EL0 as key (Linux path).
  //
  // The TLS table has 16-byte entries: [key(8), host_tls(8)].
  //   macOS: key = TPIDRRO_EL0, Linux: key = guest_tpidr
  // Sentinel entry has key = 0xFFFFFFFFFFFFFFFF.
  //
  // The stack frame must match syscall_callback's expectations:
  //   macOS: 48 bytes ([SP+0..47], SP+48 = original guest SP)
  //   Linux: 32 bytes ([SP+0..31], SP+32 = original guest SP)
  // Since syscall_callback computes guest SP as SP+48 on macOS and SP+32
  // on Linux, we use the appropriate frame size per platform.
  //
  //   [SP+0]  = saved x16
  //   [SP+8]  = saved x17
  //   [SP+16] = saved x30
  //   [SP+24] = guest_tpidr
  //   [SP+32] = guest_x18  (macOS only, not read by callback but needed for frame size)
  //   [SP+40] = host_tls   (macOS only, written by do_syscall for syscall_callback)
  //
  // Flow:
  //   1. Read TPIDRRO_EL0; if non-zero → macOS path (48B frame, TPIDRRO key, TCB tpidr)
  //      else → Linux path (32B frame, TPIDR_EL0 key on stack)
  //   2. Scan TLS table for matching entry
  //   3. Store host_tls to [SP+40] for syscall_callback (macOS)
  //      or set x18 = host_tls (Linux)
  //   4. Set x30 = return address, BR to callback
  uint64_t tls_table = tls_table_ptr;
  __asm__ volatile(
    // Read TPIDRRO_EL0 to detect platform.
    // We use x16 (not x18) because XNU zeros x18 on every
    // kernel→userspace transition (preemptive context switches).
    "mrs  x16, tpidrro_el0\n"       // x16 = TPIDRRO_EL0
    "cbnz x16, 10f\n"               // non-zero → macOS path

    // ---- Linux path: 32-byte frame, TPIDR_EL0 keyed ----
    "sub  sp, sp, #32\n"
    "str  x16, [sp, #0]\n"
    "str  x17, [sp, #8]\n"
    "str  x30, [sp, #16]\n"
    "mrs  x18, tpidr_el0\n"         // x18 = guest TPIDR (lookup key on Linux)
    "str  x18, [sp, #24]\n"         // save guest_tpidr on stack
    "mov  x17, %[tls_table]\n"      // x17 = TLS table base
    "cbz  x17, 2f\n"                // skip lookup if NULL
    "1:\n"                           // .Lloop_linux
    "ldr  x16, [x17, #0]\n"         // x16 = entry.guest_tpidr
    "cmn  x16, #1\n"                // sentinel?
    "b.eq 5f\n"                      // -> fallback to entry[0]
    "cmp  x16, x18\n"               // match?
    "b.eq 3f\n"                      // -> found
    "add  x17, x17, #16\n"          // next entry
    "b    1b\n"                      // -> loop
    "3:\n"                           // .Lfound_linux
    "ldr  x18, [x17, #8]\n"         // x18 = host_tls
    "b    2f\n"                      // -> done
    "5:\n"                           // .Lfallback_linux
    // No match — TPIDR_EL0 was clobbered by host context switch.
    // Fall back to entry[0] (correct for single-thread, best-effort for multi).
    "mov  x17, %[tls_table]\n"      // reload table base
    "ldr  x16, [x17, #0]\n"         // entry[0].guest_tpidr
    "str  x16, [sp, #24]\n"         // fix guest_tpidr on stack
    "ldr  x18, [x17, #8]\n"         // x18 = entry[0].host_tls
    "2:\n"                           // .Ldone_linux
    "adr  x30, 4f\n"                // x30 = return address
    "mov  x16, %[entry]\n"
    "br   x16\n"                     // jump to syscall_callback

    // ---- macOS path: 48-byte frame, TPIDRRO_EL0 keyed ----
    // x18 is NOT used anywhere in this path — XNU may zero it at any time.
    "10:\n"                          // .Lmacos
    "sub  sp, sp, #48\n"
    "str  x16, [sp, #0]\n"
    "str  x17, [sp, #8]\n"
    "str  x30, [sp, #16]\n"
    // Store TPIDRRO_EL0 at [SP+32] (guest_x18 slot) so the loop can
    // reload it without re-reading the system register each iteration.
    // x16 still holds TPIDRRO_EL0 from the mrs above.
    "str  x16, [sp, #32]\n"         // stash TPIDRRO_EL0 for loop
    "mov  x17, %[tls_table]\n"      // x17 = TLS table base
    "cbz  x17, 12f\n"               // skip lookup if NULL
    "11:\n"                          // .Lloop_macos
    "ldr  x16, [x17, #0]\n"         // x16 = entry.tpidrro_el0
    "cmn  x16, #1\n"                // sentinel?
    "b.eq 16f\n"                     // -> trap (TPIDRRO is stable, no fallback needed)
    "ldr  x30, [sp, #32]\n"         // x30 = our TPIDRRO_EL0 (stashed)
    "cmp  x16, x30\n"               // match TPIDRRO_EL0?
    "b.eq 13f\n"                     // -> found
    "add  x17, x17, #16\n"          // next entry
    "b    11b\n"                     // -> loop
    "13:\n"                          // .Lfound_macos
    "ldr  x17, [x17, #8]\n"         // x17 = host_tls (safe register, survives preemption)
    "ldr  x16, [x17, #24]\n"        // x16 = TCB.guest_tpidr
    "str  x16, [sp, #24]\n"         // frame.guest_tpidr = TCB.guest_tpidr
    "str  x17, [sp, #40]\n"         // frame.host_tls for syscall_callback
    "12:\n"                          // .Ldone_macos
    "adr  x30, 4f\n"                // x30 = return address (overwrites borrowed x30)
    "mov  x16, %[entry]\n"
    "br   x16\n"                     // jump to syscall_callback
    "16:\n"                          // .Ltrap_macos
    "brk  #1\n"                      // unreachable: unknown thread

    "4:\n"                           // return point (shared by both paths)
    : "+r"(x0)
    : [entry] "r"(syscall_entry), [tls_table] "r"(tls_table),
      "r"(x1), "r"(x2), "r"(x3),
      "r"(x4), "r"(x5), "r"(x8)
    : "x16", "x17", "x18", "x30", "memory"
  );
  return x0;
#endif
}

/* Re-implement some utility functions and re-define the structures to avoid
 * dependency on libc. */

// Define the FileStat structure
#ifdef __x86_64__
struct FileStat {
  unsigned long st_dev;
  unsigned long st_ino;
  unsigned long st_nlink;

  unsigned int st_mode;
  unsigned int st_uid;
  unsigned int st_gid;
  unsigned int __pad0;
  unsigned long st_rdev;
  long st_size;
  long st_blksize;
  long st_blocks; /* Number 512-byte blocks allocated. */

  unsigned long st_atime;
  unsigned long st_atime_nsec;
  unsigned long st_mtime;
  unsigned long st_mtime_nsec;
  unsigned long st_ctime;
  unsigned long st_ctime_nsec;
  long __unused[3];
};
#elif defined(__aarch64__)
// ARM64 uses the asm-generic stat layout
struct FileStat {
  unsigned long st_dev;
  unsigned long st_ino;
  unsigned int  st_mode;
  unsigned int  st_nlink;
  unsigned int  st_uid;
  unsigned int  st_gid;
  unsigned long st_rdev;
  unsigned long __pad1;
  long          st_size;
  int           st_blksize;
  int           __pad2;
  long          st_blocks;
  unsigned long st_atime;
  unsigned long st_atime_nsec;
  unsigned long st_mtime;
  unsigned long st_mtime_nsec;
  unsigned long st_ctime;
  unsigned long st_ctime_nsec;
  unsigned int  __unused4;
  unsigned int  __unused5;
};
#endif

int memcmp(const void *s1, const void *s2, size_t n) {
  const unsigned char *p1 = s1;
  const unsigned char *p2 = s2;
  while (n--) {
    if (*p1 != *p2) {
      return *p1 - *p2;
    }
    p1++;
    p2++;
  }
  return 0;
}

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(unsigned char *)s1 - *(unsigned char *)s2;
}

char *strncpy(char *dest, const char *src, size_t n) {
  char *d = dest;
  const char *s = src;
  while (n-- && *s) {
    *d++ = *s++;
  }
  while (n--) {
    *d++ = '\0';
  }
  return dest;
}

static uint64_t read_u64(const void *p) {
  uint64_t v;
  __builtin_memcpy(&v, p, 8);
  return v;
}

static size_t align_up(size_t val, size_t align) {
  size_t result = (val + align - 1) & ~(align - 1);
  // Check for overflow (result < val means we wrapped)
  if (result < val) return (size_t)-1;
  return result;
}

unsigned int la_version(unsigned int version __attribute__((unused))) {
  return LAV_CURRENT;
}

/// print value in hex
void print_hex(uint64_t data) {
#ifdef DEBUG
  for (int i = 15; i >= 0; i--) {
    unsigned char byte = (data >> (i * 4)) & 0xF;
    if (byte < 10) {
      syscall_print((&"0123456789"[byte]), 1);
    } else {
      syscall_print((&"abcdef"[byte - 10]), 1);
    }
  }
  syscall_print("\n", 1);
#endif
}

/// @brief Parse object to find the syscall entry point and the interpreter
/// path.
///
/// The trampoline is already mapped by the litebox loader at (base + vaddr).
/// The entry point is at offset 0 of the mapped trampoline. The litebox loader
/// already validated the magic when parsing the file header.
///
/// On aarch64, the rewriter extends the last PT_LOAD's p_memsz to cover the
/// trampoline region. The trampoline vaddr is align_up(max original p_memsz end),
/// but the in-memory program headers show the EXTENDED p_memsz. We scan pages
/// starting from align_up(max p_filesz end) looking for the callback pointer
/// (non-zero qword) which the litebox loader writes at trampoline offset 0.
/// BSS pages between filesz and the trampoline are zero-filled.
///
/// On x86_64, p_memsz is not extended, so align_up(max p_memsz end) works directly.
int parse_object(const struct link_map *map) {
  unsigned long max_memsz_end = 0;
  unsigned long max_filesz_end = 0;
  Elf64_Ehdr *eh = (Elf64_Ehdr *)map->l_addr;
  if (memcmp(eh->e_ident,
             "\x7f"
             "ELF",
             4) != 0) {
    syscall_print("[audit] not an ELF file\n", 24);
    return 1;
  }
  Elf64_Phdr *phdrs = (Elf64_Phdr *)((char *)map->l_addr + eh->e_phoff);
  for (int i = 0; i < eh->e_phnum; i++) {
    if (phdrs[i].p_type == PT_LOAD) {
      unsigned long memsz_end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
      unsigned long filesz_end = phdrs[i].p_vaddr + phdrs[i].p_filesz;
      if (memsz_end > max_memsz_end) max_memsz_end = memsz_end;
      if (filesz_end > max_filesz_end) max_filesz_end = filesz_end;
    } else if (phdrs[i].p_type == PT_INTERP) {
      strncpy(interp, (char *)map->l_addr + phdrs[i].p_vaddr,
              sizeof(interp) - 1);
      interp[sizeof(interp) - 1] = '\0'; // Ensure null termination
    }
  }

#ifdef __aarch64__
  // On aarch64, the rewriter extended p_memsz to cover the trampoline,
  // so max_memsz_end points past the trampoline. The trampoline is between
  // the file-backed data (filesz) and the extended memsz. Scan pages from
  // align_up(max_filesz_end) looking for the callback pointer (non-zero).
  unsigned long scan_start = align_up(max_filesz_end, 0x1000);
  unsigned long scan_end = align_up(max_memsz_end, 0x1000);
  void *trampoline_addr = 0;
  for (unsigned long offset = scan_start; offset < scan_end; offset += 0x1000) {
    uint64_t val = read_u64((const char *)map->l_addr + offset);
    if (val != 0) {
      trampoline_addr = (void *)map->l_addr + offset;
      break;
    }
  }
  if (!trampoline_addr) {
    syscall_print("[audit] trampoline not found in scan\n", 37);
    return 1;
  }
#else
  // On x86_64, p_memsz is not extended, so the trampoline is right after.
  unsigned long tramp_start = align_up(max_memsz_end, 0x1000);
  void *trampoline_addr = (void *)map->l_addr + tramp_start;
#endif

  // The trampoline code has the syscall entry point at offset 0.
  syscall_entry = (syscall_stub_t)read_u64(trampoline_addr);
  if (syscall_entry == 0) {
    syscall_print("[audit] syscall entry is null\n", 30);
    return 1;
  }
#ifdef __aarch64__
  // Read the TLS lookup table pointer at offset 8.
  // This is written by the litebox loader at trampoline_start + 8.
  tls_table_ptr = read_u64((const char *)trampoline_addr + 8);
#endif
  print_hex((uint64_t)syscall_entry);
  return 0;
}

unsigned int la_objopen(struct link_map *map,
                        Lmid_t lmid __attribute__((unused)),
                        uintptr_t *cookie __attribute__((unused))) {
  syscall_print("[audit] la_objopen called\n", 26);
  const char *path = map->l_name;

  if (!path || path[0] == '\0') {
    // main binary should be called first.
    if (map->l_addr != 0) {
      // `map->l_addr` is zero for the main binary if it is not position
      // independent.
      if (parse_object(map) != 0) {
        syscall_print("[audit] failed to parse main binary\n", 36);
        return 0;
      }
      syscall_print("[audit] main binary is patched by libOS\n", 40);
      syscall_print("[audit] interp=", 15);
      syscall_print(interp, sizeof(interp) - 1);
      syscall_print("\n", 1);
    }
    return 0; // main binary is patched by libOS
  }

  if (syscall_entry == 0) {
    // failed to get the syscall entry point from the main binary
    // fall back to get it from ld-*.so, which should be called next.
    if (parse_object(map) != 0) {
      syscall_print("[audit] failed to parse ld\n", 27);
      return 0;
    }
    syscall_print("[audit] ld is patched by libOS: \n", 33);
    syscall_print(path, 32);
    syscall_print("\n", 1);
    return 0; // ld.so is patched by libOS
  }

  if (interp[0] != '\0' && strcmp(path, interp) == 0) {
    // successfully get the entry point and interpreter from the main binary
    syscall_print("[audit] ld-*.so is patched by libOS\n", 36);
    return 0; // ld.so is patched by libOS
  }

  // Other shared libraries
  syscall_print("[audit] la_objopen: path=", 25);
  syscall_print(path, 32);
  syscall_print("\n", 1);

  if (!syscall_entry) {
    return 0;
  }

  int fd = do_syscall(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
  if (fd < 0) {
    syscall_print("[audit] failed to open file\n", 28);
    return 0;
  }

  struct FileStat st;
#ifdef __x86_64__
  if (do_syscall(SYS_fstat, fd, (long)&st, 0, 0, 0, 0) < 0) {
#elif defined(__aarch64__)
  #define AT_EMPTY_PATH 0x1000
  if (do_syscall(SYS_newfstatat, fd, (long)"", (long)&st, AT_EMPTY_PATH, 0, 0) < 0) {
#endif
    syscall_print("[audit] fstat failed\n", 21);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }
  long file_size = st.st_size;

  // File must be large enough to contain at least a trampoline header
  if (file_size < (long)sizeof(struct TrampolineHeader)) {
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // The trampoline header is at the end of the file (last 32 bytes).
  // File layout: [ELF][padding][trampoline code][header]
  // Read the last page that contains the header.
  long header_offset = file_size - sizeof(struct TrampolineHeader);
  long header_page_offset = header_offset & ~0xFFFUL;

  // Map the page containing the header
  void *header_page = (void *)do_syscall(SYS_mmap, 0, 0x1000, PROT_READ, MAP_PRIVATE, fd, header_page_offset);
  if ((uintptr_t)header_page >= (uintptr_t)-4096) {
    syscall_print("[audit] mmap header page failed\n", 32);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Read header from the mapped page
  long header_in_page_offset = header_offset - header_page_offset;
  const struct TrampolineHeader *header = (const struct TrampolineHeader *)((const char *)header_page + header_in_page_offset);

  // Check magic
  if (header->magic != TRAMPOLINE_MAGIC) {
    // If the prefix matches but the version differs, fail explicitly.
    if (memcmp(header, "LITEBOX", 7) == 0) {
      syscall_print("[audit] invalid trampoline version\n", 36);
      do_syscall(SYS_munmap, (long)header_page, 0x1000, 0, 0, 0, 0);
      do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
      return 0;
    }
    // No trampoline found
    do_syscall(SYS_munmap, (long)header_page, 0x1000, 0, 0, 0, 0);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Copy fields before unmapping
  uint64_t tramp_file_offset = header->file_offset;
  uint64_t tramp_vaddr = header->vaddr;
  uint64_t tramp_size_raw = header->trampoline_size;

  do_syscall(SYS_munmap, (long)header_page, 0x1000, 0, 0, 0, 0);
  syscall_print("[audit] found trampoline header at end of file\n", 47);

  // Validate trampoline size
  if (tramp_size_raw == 0) {
    syscall_print("[audit] trampoline code size invalid\n", 37);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Verify file offset is page-aligned
  if ((tramp_file_offset & 0xFFF) != 0) {
    syscall_print("[audit] trampoline code not page-aligned\n", 41);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // The trampoline code should immediately precede the header.
  if (tramp_file_offset + tramp_size_raw != (uint64_t)header_offset) {
    syscall_print("[audit] trampoline extends beyond header\n", 41);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Validate tramp_vaddr is within reasonable userspace bounds and page-aligned
  if (tramp_vaddr > MAX_USERSPACE_ADDR || (tramp_vaddr & 0xFFF) != 0) {
    syscall_print("[audit] trampoline vaddr out of bounds\n", 39);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  uint64_t tramp_addr = map->l_addr + tramp_vaddr;
  uint64_t tramp_size = align_up(tramp_size_raw, 0x1000);

  // Check for overflow in align_up or address calculation
  if (tramp_size == (size_t)-1 || tramp_addr < map->l_addr) {
    syscall_print("[audit] trampoline size/addr overflow\n", 38);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  syscall_print("[audit] tramp base=", 19);
  print_hex(map->l_addr);
  syscall_print("[audit] tramp vaddr=", 20);
  print_hex(tramp_vaddr);
  syscall_print("[audit] tramp_addr=", 19);
  print_hex(tramp_addr);
  syscall_print("[audit] tramp_size_raw=", 23);
  print_hex(tramp_size_raw);
  syscall_print("[audit] tramp_size_aligned=", 27);
  print_hex(tramp_size);
  syscall_print("[audit] file_offset=", 20);
  print_hex(tramp_file_offset);

  // Map the trampoline at the expected address using MAP_FIXED.
  // The rewriter extended the last PT_LOAD segment's p_memsz to cover the
  // trampoline region, so ld.so's initial reservation already includes this
  // address range (as PROT_NONE pages). MAP_FIXED safely replaces those pages.
  void *mapped =
      (void *)do_syscall(SYS_mmap, tramp_addr, tramp_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  if ((uintptr_t)mapped >= (uintptr_t)-4096) {
    syscall_print("[audit] mmap MAP_FIXED failed\n", 30);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }
  syscall_print("[audit] mmap OK at ", 19);
  print_hex((uint64_t)(uintptr_t)mapped);

  // Seek to the trampoline data in the file and read it into the mapping.
  long seek_ret = do_syscall(SYS_lseek, fd, tramp_file_offset, SEEK_SET, 0, 0, 0);
  if (seek_ret < 0) {
    syscall_print("[audit] lseek failed\n", 21);
    do_syscall(SYS_munmap, (long)mapped, tramp_size, 0, 0, 0, 0);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Read trampoline data (may need multiple read calls for large trampolines)
  uint64_t total_read = 0;
  while (total_read < tramp_size_raw) {
    long n = do_syscall(SYS_read, fd, (long)((char *)mapped + total_read),
                        tramp_size_raw - total_read, 0, 0, 0);
    if (n <= 0) {
      syscall_print("[audit] read trampoline data failed\n", 36);
      do_syscall(SYS_munmap, (long)mapped, tramp_size, 0, 0, 0, 0);
      do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
      return 0;
    }
    total_read += n;
  }
  syscall_print("[audit] read OK, total_read=", 28);
  print_hex(total_read);

  // Write the syscall entry point at the start of the trampoline code
  __builtin_memcpy((char *)mapped, (const void *)&syscall_entry, 8);
#ifdef __aarch64__
  // Write the TLS lookup table pointer at offset 8 of the trampoline.
  // The per-SVC trampoline snippets load this to look up the host TLS base.
  // This pointer was obtained from the main binary's trampoline in parse_object.
  if (tls_table_ptr != 0) {
    __builtin_memcpy((char *)mapped + 8, (const void *)&tls_table_ptr, 8);
  }
#endif
  do_syscall(SYS_mprotect, (long)mapped, tramp_size, PROT_READ | PROT_EXEC, 0,
             0, 0);
  syscall_print("[audit] trampoline patched and protected\n", 41);

  do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
  return 0;
}
