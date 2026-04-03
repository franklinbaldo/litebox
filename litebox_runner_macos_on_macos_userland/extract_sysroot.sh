#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# extract_sysroot.sh — Extract dylibs from macOS shared cache for testing.
#
# On modern macOS, individual dylib files (like /usr/lib/libSystem.B.dylib)
# don't exist on the filesystem — they live only in the dyld shared cache.
# This script compiles a small C program that calls the system's
# dsc_extractor.bundle to extract all dylibs to a target directory.
#
# Usage: ./extract_sysroot.sh <sysroot-dir>

set -e

SYSROOT="$1"
if [ -z "$SYSROOT" ]; then
    echo "Usage: $0 <sysroot-dir>"
    exit 1
fi

mkdir -p "$SYSROOT"

CACHE="/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
EXTRACTOR="/usr/lib/dsc_extractor.bundle"

if [ ! -f "$CACHE" ]; then
    echo "ERROR: Shared cache not found at $CACHE"
    exit 1
fi

if [ ! -f "$EXTRACTOR" ]; then
    echo "ERROR: dsc_extractor.bundle not found at $EXTRACTOR"
    exit 1
fi

# Compile a small extractor program
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/extract.c" << 'CEOF'
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*extractor_func)(const char*, const char*, void (^)(unsigned, unsigned));

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <cache-path> <output-dir>\n", argv[0]);
        return 1;
    }

    void *handle = dlopen("/usr/lib/dsc_extractor.bundle", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    extractor_func extract = (extractor_func)dlsym(handle, "dyld_shared_cache_extract_dylibs_progress");
    if (!extract) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    printf("Extracting dylibs from %s to %s...\n", argv[1], argv[2]);
    int result = extract(argv[1], argv[2], ^(unsigned current, unsigned total) {
        if (current % 50 == 0 || current == total) {
            printf("  %u / %u\n", current, total);
        }
    });

    dlclose(handle);

    if (result == 0) {
        printf("Extraction complete!\n");
    } else {
        fprintf(stderr, "Extraction failed with code %d\n", result);
    }
    return result;
}
CEOF

clang -o "$TMPDIR/extract" "$TMPDIR/extract.c" -ldl 2>/dev/null || \
clang -o "$TMPDIR/extract" "$TMPDIR/extract.c"

"$TMPDIR/extract" "$CACHE" "$SYSROOT"
