// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

.global _start
.align 4

_start:
    mov x0, #42         // status = 42
    mov x16, #1         // SYS_exit = 1
    svc #0x80
