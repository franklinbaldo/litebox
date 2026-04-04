// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

.global _start
.align 4

_start:
    // write(1, msg, 6)
    mov x0, #1          // fd = stdout
    adrp x1, msg@PAGE
    add x1, x1, msg@PAGEOFF
    mov x2, #6          // count = 6
    mov x16, #4         // SYS_write = 4
    svc #0x80

    // exit(0)
    mov x0, #0          // status = 0
    mov x16, #1         // SYS_exit = 1
    svc #0x80

.data
msg:
    .asciz "hello\n"
