# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

SRC = rtld_audit.c
OUT_DIR ?= .
OUTPUT = $(OUT_DIR)/litebox_rtld_audit.so
CC ?= cc
CFLAGS ?= -Wall -Werror -fPIC -shared -nostdlib -fno-stack-protector
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
    CFLAGS += -m64
else ifeq ($(ARCH),aarch64)
    # Reserve X18 so it's never used as a GPR. On Windows ARM64, X18 is the
    # TEB pointer and must not be clobbered. On macOS, the kernel zeros X18
    # on exception entry. This flag ensures the audit library is safe to run
    # without syscall-rewriter X18 virtualization on all platforms.
    CFLAGS += -ffixed-x18
else
    $(error Unsupported target architecture: $(ARCH))
endif
ifdef DEBUG
    CFLAGS += -DDEBUG
endif
all: $(OUTPUT)

$(OUTPUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
