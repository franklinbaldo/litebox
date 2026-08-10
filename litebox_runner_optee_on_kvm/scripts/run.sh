#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Build litebox_runner_optee_on_kvm and boot it under QEMU, end to end.
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
# 0x20 on failure; see `debug_exit` in litebox_platform_lvbs/src/host/kvm/mod.rs.
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
COMMANDS=""
SOCKET=""
# Defaults for -c: the same artifacts litebox_runner_optee_on_linux_userland's
# tests use, taken *unrewritten*. See client.py's module docstring for why the
# KVM runner must not use the rewriter's output.
TA_DIR="$REPO_ROOT/litebox_runner_optee_on_linux_userland/tests"
LDELF="$TA_DIR/ldelf.elf"
TA="$TA_DIR/hello-ta.elf"

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
  -c FILE   Drive the guest over the virtio message channel with the JSON
            command sequence in FILE, instead of letting it run its embedded
            TA sequence. Adds a virtio-serial-pci device and a unix-socket
            chardev to the QEMU line and runs scripts/client.py against it.
            Try litebox_runner_optee_on_linux_userland/tests/hello-ta-cmds.json.
  -l FILE   ldelf.elf to ship to the guest with -c
            (default: $LDELF).
  -a FILE   TA .elf to ship to the guest with -c
            (default: $TA). Both are the raw,
            *unrewritten* binaries: under KVM LiteBox is the kernel, so the
            TA's own syscall instructions trap to syscall_entry and
            litebox_syscall_rewriter's output would be wrong.
  -S PATH   Socket path for -c (default: a fresh one under \$TMPDIR).
  -t SECS   Timeout in seconds (default: $TIMEOUT)
  -d        Add QEMU interrupt/reset tracing (-d int,cpu_reset). Useful when
            the guest triple-faults, which is otherwise silent.

Exit status mirrors the guest:
  $EXIT_SUCCESS  guest completed successfully
  $EXIT_GUEST_FAILURE  guest panicked
  $EXIT_TIMEOUT  timed out (hung, or triple-faulted into a reset loop)

With -c the script's own status is 0 only if *both* the client and the guest
succeeded; the client's failure is reported in preference to the guest's,
because it is the one that says what went wrong with the exchange.
EOF
}

while getopts ":hkrbsm:i:t:dc:S:l:a:" opt; do
    case $opt in
        h) usage; exit 0 ;;
        k) ACCEL=1 ;;
        r) PROFILE="release" ;;
        b) BUILD_ONLY=1 ;;
        s) SKIP_BUILD=1 ;;
        m) MEMORY="$OPTARG" ;;
        i) INITRD="$OPTARG" ;;
        c) COMMANDS="$OPTARG" ;;
        l) LDELF="$OPTARG" ;;
        a) TA="$OPTARG" ;;
        S) SOCKET="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        d) DEBUG_QEMU=1 ;;
        \?) usage; fatal "Unknown option: -$OPTARG" ;;
        :)  usage; fatal "Option -$OPTARG requires an argument" ;;
    esac
done

TARGET_JSON="$CRATE_DIR/x86_64_kvm.json"
TARGET_NAME=$( basename "$TARGET_JSON" .json )
BIN="$REPO_ROOT/target/$TARGET_NAME/$PROFILE/litebox_runner_optee_on_kvm"

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

    info "Building litebox_runner_optee_on_kvm ($PROFILE, $CHANNEL)"
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

# `-display none -serial stdio` rather than `-nographic`.
#
# `-nographic` expands to `-display none -serial mon:stdio`. The `mon:` mux
# adds the QEMU monitor and the Ctrl-A escape, neither of which a
# non-interactive run needs, and it swallows Ctrl-C. Without the mux the
# serial console is plain stdout and Ctrl-C kills QEMU normally.
#
# Ctrl-C reaches QEMU and kills it, which is what you want from a run script.
QEMU_ARGS=(
    -machine q35
    -m "$MEMORY"
    -kernel "$BIN"
    -display none
    -serial stdio
    -no-reboot
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
)

[ -n "$INITRD" ] && {
    [ -f "$INITRD" ] || fatal "initrd not found: $INITRD"
    QEMU_ARGS+=( -initrd "$INITRD" )
}

# The virtio message channel.
#
# `disable-legacy=on` makes the device modern-only (PCI device id 0x1043
# rather than the transitional 0x1003). The guest driver only ever spoke the
# modern interface; saying so on the command line makes that a contract
# instead of an accident.
#
# The *client* serves the socket and QEMU connects to it, which is the reverse
# of the obvious arrangement and is deliberate. With `-k` the user may not be
# in the `kvm` group, so QEMU runs under `sudo`; were QEMU the server it would
# create the socket owned by root and client.py, running as the ordinary user,
# would get EACCES. Root can connect to a socket owned by anyone, so serving
# from the client works under either privilege arrangement. It also removes
# the startup race: we wait for the socket to exist before starting QEMU.
if [ -n "$COMMANDS" ]; then
    [ -f "$COMMANDS" ] || fatal "command sequence not found: $COMMANDS"
    command -v python3 >/dev/null || fatal "python3 not found, but -c needs it"
    [ -f "$LDELF" ] || fatal "ldelf not found: $LDELF"
    [ -f "$TA" ] || fatal "TA not found: $TA"
    CLIENT="$SCRIPT_DIR/client.py"
    [ -f "$CLIENT" ] || fatal "client not found at $CLIENT"
    if [ -z "$SOCKET" ]; then
        SOCKET="${TMPDIR:-/tmp}/litebox-optee-$$.sock"
    fi
    rm -f "$SOCKET"
    QEMU_ARGS+=(
        -chardev "socket,id=optee,path=$SOCKET"
        -device virtio-serial-pci,id=vs0,disable-legacy=on
        -device virtconsole,chardev=optee,bus=vs0.0
    )
fi

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

# Two details here are load-bearing:
#
# `timeout --foreground`: without it, GNU timeout runs its child in a *new
# process group* so it can signal the whole group on expiry. That leaves QEMU
# in a background process group relative to the controlling terminal, so the
# tcsetattr() its stdio chardev performs raises SIGTTOU and stops the process.
# The symptom is a run that prints nothing at all and then hits the timeout,
# with no indication why. QEMU is a single process here, so the process group
# buys nothing and --foreground costs nothing. `dev_tests/tests/kvm_qemu_boot.rs`
# uses the same form.
#
# `--kill-after`: SIGTERM asks QEMU to exit; if it does not, follow up with
# SIGKILL rather than leaving a VM running.
#
# No pipe: QEMU inherits stdin, stdout and stderr directly, so $? is QEMU's
# own status rather than a filter's, nothing buffers or reorders the guest's
# output, and the serial console stays interactive.
set +e
if [ -n "$COMMANDS" ]; then
    # The client starts first because it serves the socket (see above). Both
    # run in the background so this script can wait on the client's verdict
    # first: it is the side that finishes deterministically, and it is the one
    # that can say what went wrong with the exchange.
    #
    # Both keep stdout and stderr, so the guest's serial log interleaves with
    # the client's output in the order things happened, which is the whole
    # value of having both.
    python3 "$CLIENT" "$SOCKET" "$LDELF" "$TA" "$COMMANDS" --timeout "$TIMEOUT" &
    CLIENT_PID=$!

    # Wait for the client to bind before QEMU tries to connect; QEMU exits
    # immediately if the socket is not there yet. Bounded, because a client
    # that died during startup must not hang the script.
    SOCKET_WAIT=0
    while [ ! -S "$SOCKET" ]; do
        kill -0 "$CLIENT_PID" 2>/dev/null || fatal "client exited before binding $SOCKET"
        SOCKET_WAIT=$((SOCKET_WAIT + 1))
        [ "$SOCKET_WAIT" -gt 200 ] && fatal "client did not bind $SOCKET within 10s"
        sleep 0.05
    done

    $PRIVILEGE timeout --foreground --kill-after=10 "$TIMEOUT" \
        qemu-system-x86_64 "${QEMU_ARGS[@]}" </dev/null &
    QEMU_PID=$!

    wait "$CLIENT_PID"
    CLIENT_STATUS=$?
    # A client that gave up will never send the Shutdown the guest is waiting
    # for, so waiting for the guest would cost its whole request deadline and
    # then report a panic that is a consequence of the failure rather than the
    # failure. Kill it and report the client's verdict.
    if [ "$CLIENT_STATUS" -ne 0 ]; then
        kill "$QEMU_PID" 2>/dev/null
    fi
    wait "$QEMU_PID"
    STATUS=$?
    rm -f "$SOCKET"
else
    $PRIVILEGE timeout --foreground --kill-after=10 "$TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}"
    STATUS=$?
    CLIENT_STATUS=0
fi
set -e

echo 1>&2

# The client's verdict comes first. A guest that exited cleanly while the
# client was reporting a protocol or TA error is still a failed run, and the
# client's message is the one that says why.
if [ "$CLIENT_STATUS" -ne 0 ]; then
    fatal "Client failed (exit $CLIENT_STATUS). The [client] FAILED line above has the reason."
fi

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
