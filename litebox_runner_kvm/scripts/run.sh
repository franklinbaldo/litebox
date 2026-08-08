#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Build litebox_runner_kvm and boot it under QEMU, end to end.
#
# The runner boots via the PVH boot protocol, brings up a full kernel
# environment (heap, GDT/IDT, DEP page tables, SMEP/SMAP), loads OP-TEE's
# `ldelf`, and executes a Trusted Application in ring 3 before exiting through
# QEMU's `isa-debug-exit` device.

set -eo pipefail

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd -P )
CRATE_DIR=$( cd "$SCRIPT_DIR/.." && pwd -P )
REPO_ROOT=$( cd "$CRATE_DIR/.." && pwd -P )

RED="\033[0;31m"
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
BOLD="\033[1m"
RESET="\033[0m"

fatal() { echo -e "${RED}${BOLD}[!]${RESET} $1" 1>&2; exit 1; }
warn()  { echo -e "${YELLOW}${BOLD}[*]${RESET} $1" 1>&2; }
info()  { echo -e "${GREEN}${BOLD}[+]${RESET} $1" 1>&2; }

# The guest ends by writing to `isa-debug-exit`, which QEMU turns into the
# process status `(value << 1) | 1`. The runner writes 0x10 on success and
# 0x20 on failure; see `debug_exit` in litebox_platform_lvbs/src/host/kvm_impl.rs.
EXIT_SUCCESS=33
EXIT_GUEST_FAILURE=65
EXIT_TIMEOUT=124

ACCEL=0
BUILD_ONLY=0
SKIP_BUILD=0
DEBUG_QEMU=0
PROFILE="debug"
MEMORY="512M"
TIMEOUT=120
INITRD=""

usage() {
    cat 1>&2 <<EOF
Usage: $0 [options]

  -h        Show this help message
  -k        Use hardware acceleration (KVM). Requires access to /dev/kvm;
            falls back to sudo -n if the current user lacks it.
  -r        Build with --release instead of debug
  -b        Build only, do not run
  -s        Skip the build, run the existing binary
  -m MEM    Guest memory (default: $MEMORY). Try 32M to exercise the
            allocation-failure path.
  -i FILE   Attach FILE as an initrd. Exercises the module-reservation path
            in the memory map, which must withhold it from the heap.
  -t SECS   Timeout in seconds (default: $TIMEOUT)
  -d        Add QEMU interrupt/reset tracing (-d int,cpu_reset). Useful when
            the guest triple-faults, which is otherwise silent.

Exit status mirrors the guest:
  $EXIT_SUCCESS  guest completed successfully
  $EXIT_GUEST_FAILURE  guest panicked
  $EXIT_TIMEOUT  timed out (hung, or triple-faulted into a reset loop)
EOF
}

while getopts ":hkrbsm:i:t:d" opt; do
    case $opt in
        h) usage; exit 0 ;;
        k) ACCEL=1 ;;
        r) PROFILE="release" ;;
        b) BUILD_ONLY=1 ;;
        s) SKIP_BUILD=1 ;;
        m) MEMORY="$OPTARG" ;;
        i) INITRD="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        d) DEBUG_QEMU=1 ;;
        \?) usage; fatal "Unknown option: -$OPTARG" ;;
        :)  usage; fatal "Option -$OPTARG requires an argument" ;;
    esac
done

TARGET_JSON="$CRATE_DIR/x86_64_kvm.json"
TARGET_NAME=$( basename "$TARGET_JSON" .json )
BIN="$REPO_ROOT/target/$TARGET_NAME/$PROFILE/litebox_runner_kvm"

# ---------------------------------------------------------------------------
# Build.
#
# The crate needs a custom bare-metal target, which in turn needs `-Z
# build-std` to compile core/alloc from source, which needs nightly. The
# channel is read from the crate's own rust-toolchain.toml rather than
# hardcoded, because rustup selects by working directory and the workspace
# root pins stable.
# ---------------------------------------------------------------------------
if [ "$SKIP_BUILD" -eq 0 ]; then
    command -v cargo >/dev/null || fatal "cargo not found"

    CHANNEL=$( awk -F'"' '/^channel/{print $2}' "$CRATE_DIR/rust-toolchain.toml" )
    [ -n "$CHANNEL" ] || fatal "could not read channel from $CRATE_DIR/rust-toolchain.toml"

    if ! rustup run "$CHANNEL" rustc --version >/dev/null 2>&1; then
        fatal "toolchain '$CHANNEL' is not installed. Try:
    rustup toolchain install $CHANNEL --component rust-src"
    fi

    RELEASE_FLAG=""
    [ "$PROFILE" = "release" ] && RELEASE_FLAG="--release"

    info "Building litebox_runner_kvm ($PROFILE, $CHANNEL)"
    ( cd "$REPO_ROOT" && cargo "+$CHANNEL" build $RELEASE_FLAG \
        -Z build-std-features=compiler-builtins-mem \
        -Z build-std=core,alloc \
        --manifest-path "$CRATE_DIR/Cargo.toml" \
        --target "$TARGET_JSON" )
fi

[ -f "$BIN" ] || fatal "runner binary not found at $BIN"

if [ "$BUILD_ONLY" -eq 1 ]; then
    info "Built $BIN"
    exit 0
fi

# ---------------------------------------------------------------------------
# Run.
# ---------------------------------------------------------------------------
command -v qemu-system-x86_64 >/dev/null \
    || fatal "qemu-system-x86_64 not found. On Debian/Ubuntu:
    sudo apt-get install -y qemu-system-x86"

QEMU_ARGS=(
    -machine q35
    -m "$MEMORY"
    -kernel "$BIN"
    -nographic
    -no-reboot
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
)

[ -n "$INITRD" ] && {
    [ -f "$INITRD" ] || fatal "initrd not found: $INITRD"
    QEMU_ARGS+=( -initrd "$INITRD" )
}

[ "$DEBUG_QEMU" -eq 1 ] && QEMU_ARGS+=( -d int,cpu_reset )

PRIVILEGE=""
if [ "$ACCEL" -eq 1 ]; then
    # `-cpu host` exposes the physical CPU, which has RDRAND.
    QEMU_ARGS+=( -enable-kvm -cpu host )
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        sudo -n true 2>/dev/null \
            || fatal "no access to /dev/kvm and passwordless sudo unavailable.
    Add yourself to the 'kvm' group, or drop -k to use TCG emulation."
        warn "no access to /dev/kvm; escalating with sudo"
        PRIVILEGE="sudo -n"
    fi
else
    # `-cpu max` rather than QEMU's default `qemu64`, which lacks RDRAND.
    # CrngProvider panics without it. The clock's CPUID max-leaf guards
    # correctly reject the aliased leaf-0xd data that `-cpu max` exposes at
    # leaf 0x15, so PIT calibration still wins.
    QEMU_ARGS+=( -cpu max )
fi

info "Booting ($([ "$ACCEL" -eq 1 ] && echo KVM || echo TCG), $MEMORY, ${TIMEOUT}s timeout)"
echo 1>&2

set +e
$PRIVILEGE timeout "$TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" 2>&1 | tr -d '\r'
STATUS=${PIPESTATUS[0]}
set -e

echo 1>&2
case "$STATUS" in
    "$EXIT_SUCCESS")
        info "Guest completed successfully (exit $STATUS)"
        exit 0
        ;;
    "$EXIT_GUEST_FAILURE")
        fatal "Guest panicked (exit $STATUS). The PANIC line above has the reason."
        ;;
    "$EXIT_TIMEOUT")
        fatal "Timed out after ${TIMEOUT}s (exit $STATUS).
    The guest hung, or triple-faulted into a reset loop. Re-run with -d to
    dump the interrupt and reset state."
        ;;
    *)
        fatal "QEMU exited with an unexpected status: $STATUS"
        ;;
esac
