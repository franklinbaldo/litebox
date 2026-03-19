#!/usr/bin/env bash
# Run gVisor microbenchmarks under native Linux, LiteBox, or gVisor (runsc).
#
# Usage: ./run_microbenchmarks.sh <mode> [benchmark]
#   mode: native | litebox | gvisor
#   benchmark: optional, e.g. "getpid" to run only getpid_benchmark
#
# Prerequisites:
#   1. Build benchmarks statically:
#      bazel build -c opt --dynamic_mode=off --linkopt=-static \
#        //test/perf/linux:{getpid,gettid,clock_gettime,clock_getres,fork,futex,epoll,poll,select,open,read,write,open_read_close,pipe,send_recv,dup,mapping,signal,sched_yield,death,stat,getdents,unlink,sleep,randread,seqwrite}_benchmark
#
#   2. For litebox mode:
#      cd /path/to/litebox_v3
#      cargo build --release -p litebox_runner_linux_userland
#      Set LITEBOX_RUNNER env var (or it defaults to litebox_v3/target/release/litebox_runner_linux_userland)
#
#   3. For gvisor mode:
#      Install runsc: https://gvisor.dev/docs/user_guide/install/
#      Ensure 'runsc' is on PATH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GVISOR_ROOT="$SCRIPT_DIR/gvisor"

# --- Clone gVisor if not already present ---
if [[ ! -d "$GVISOR_ROOT" ]]; then
    echo "Cloning gVisor into $GVISOR_ROOT ..."
    git clone --depth 1 https://github.com/google/gvisor.git "$GVISOR_ROOT"
fi

BIN_DIR="$GVISOR_ROOT/bazel-bin/test/perf/linux"

MODE="${1:?Usage: $0 <native|litebox|gvisor> [benchmark]}"
OUTPUT_DIR="$SCRIPT_DIR/benchmark_results/$MODE"
BENCH_FILTER="${2:-}"

# Validate mode.
case "$MODE" in
    native|litebox|gvisor) ;;
    *) echo "ERROR: mode must be native, litebox, or gvisor (got: $MODE)"; exit 1 ;;
esac

# Locate LiteBox runner if needed.
if [[ "$MODE" == "litebox" ]]; then
    LITEBOX_RUNNER="${LITEBOX_RUNNER:-$(realpath "$SCRIPT_DIR/../../target/release/litebox_runner_linux_userland" 2>/dev/null || true)}"
    if [[ ! -x "$LITEBOX_RUNNER" ]]; then
        echo "ERROR: litebox_runner_linux_userland not found."
        echo "  Build it: cargo build --release -p litebox_runner_linux_userland"
        echo "  Or set LITEBOX_RUNNER=/path/to/litebox_runner_linux_userland"
        exit 1
    fi
    echo "Using LiteBox runner: $LITEBOX_RUNNER"

    # Build a tar with /proc/cpuinfo so benchmarks can read CPU info inside the sandbox.
    LITEBOX_ROOTFS_TAR="$SCRIPT_DIR/.litebox_rootfs.tar"
    if [[ ! -f "$LITEBOX_ROOTFS_TAR" ]]; then
        TMPDIR_TAR="$(mktemp -d)"
        mkdir -p "$TMPDIR_TAR/proc"
        cp /proc/cpuinfo "$TMPDIR_TAR/proc/cpuinfo"
        tar cf "$LITEBOX_ROOTFS_TAR" -C "$TMPDIR_TAR" proc
        rm -rf "$TMPDIR_TAR"
        echo "Created rootfs tar: $LITEBOX_ROOTFS_TAR"
    fi
fi

# Locate runsc if needed.
if [[ "$MODE" == "gvisor" ]]; then
    RUNSC="${RUNSC:-$(command -v runsc 2>/dev/null || true)}"
    if [[ ! -x "$RUNSC" ]]; then
        echo "ERROR: runsc not found on PATH."
        echo "  Install: https://gvisor.dev/docs/user_guide/install/"
        echo "  Or set RUNSC=/path/to/runsc"
        exit 1
    fi
    echo "Using runsc: $RUNSC"
fi

# --- Build microbenchmarks if not already built ---
BENCH_TARGETS=(
    getpid gettid clock_gettime clock_getres fork futex epoll poll select
    open read write open_read_close pipe send_recv dup mapping signal
    sched_yield death stat getdents unlink sleep randread seqwrite
)

# Check if any benchmark binary is missing and rebuild if so.
NEED_BUILD=false
for b in "${BENCH_TARGETS[@]}"; do
    if [[ ! -x "$BIN_DIR/${b}_benchmark" ]]; then
        NEED_BUILD=true
        break
    fi
done

if $NEED_BUILD; then
    echo "Building gVisor microbenchmarks (this may take a while) ..."
    BAZEL_TARGETS=()
    for b in "${BENCH_TARGETS[@]}"; do
        BAZEL_TARGETS+=("//test/perf/linux:${b}_benchmark")
    done
    (cd "$GVISOR_ROOT" && bazel build -c opt --dynamic_mode=off --linkopt=-static "${BAZEL_TARGETS[@]}")
    echo "Build complete."
fi

mkdir -p "$OUTPUT_DIR"

BENCHMARKS=(
    getpid_benchmark
    gettid_benchmark
    clock_gettime_benchmark
    clock_getres_benchmark
    fork_benchmark
    futex_benchmark
    epoll_benchmark
    poll_benchmark
    select_benchmark
    open_benchmark
    read_benchmark
    write_benchmark
    open_read_close_benchmark
    pipe_benchmark
    send_recv_benchmark
    dup_benchmark
    mapping_benchmark
    signal_benchmark
    sched_yield_benchmark
    death_benchmark
    stat_benchmark
    getdents_benchmark
    unlink_benchmark
    sleep_benchmark
    randread_benchmark
    seqwrite_benchmark
)

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
SUMMARY="$OUTPUT_DIR/summary_${MODE}_${TIMESTAMP}.txt"

echo "gVisor Microbenchmark Results [$MODE] — $(date)" | tee "$SUMMARY"
echo "Host: $(uname -n) ($(uname -r))" | tee -a "$SUMMARY"
echo "CPU: $(lscpu | grep 'Model name' | sed 's/.*: *//')" | tee -a "$SUMMARY"
echo "Mode: $MODE" | tee -a "$SUMMARY"
echo "========================================" | tee -a "$SUMMARY"
echo "" | tee -a "$SUMMARY"

for bench in "${BENCHMARKS[@]}"; do
    # If a specific benchmark was requested, skip all others.
    if [[ -n "$BENCH_FILTER" && "$bench" != "${BENCH_FILTER}_benchmark" ]]; then
        continue
    fi

    bin="$BIN_DIR/$bench"
    if [[ ! -x "$bin" ]]; then
        echo "SKIP: $bench (not built)" | tee -a "$SUMMARY"
        continue
    fi

    # sched_yield is a no-op in LiteBox, so the number is not meaningful.
    if [[ "$MODE" == "litebox" && "$bench" == "sched_yield_benchmark" ]]; then
        echo "SKIP: $bench (sched_yield is a no-op in litebox)" | tee -a "$SUMMARY"
        continue
    fi

    # death_benchmark is not useful for any mode.
    if [[ "$bench" == "death_benchmark" ]]; then
        echo "SKIP: $bench (not useful)" | tee -a "$SUMMARY"
        continue
    fi

    echo "--- $bench ---" | tee -a "$SUMMARY"

    # Build the command to run.
    case "$MODE" in
        native)      CMD=("$bin") ;;
        litebox)     CMD=("$LITEBOX_RUNNER" -Z --rewrite-syscalls --initial-files "$LITEBOX_ROOTFS_TAR" --env HOME=/ "$bin") ;;
        gvisor)      CMD=("$RUNSC" --network=none --rootless do "$bin") ;;
    esac

    # Default: run all sub-benchmarks.  Override per-benchmark for litebox when
    # some sub-benchmarks need IPv6 or other unsupported features.
    BENCH_RE=".*"
    if [[ "$MODE" == "litebox" && "$bench" == "send_recv_benchmark" ]]; then
        # BM_RecvmsgWithControlBuf needs AF_INET6; BM_SendmsgTCP needs loopback
        BENCH_RE="BM_Recvmsg/|BM_Sendmsg/|BM_Recvfrom/|BM_Sendto/"
    fi
    if [[ "$MODE" == "litebox" && "$bench" == "fork_benchmark" ]]; then
        # Exclude multi-process CPU benchmarks (Asymmetric/Symmetric) and
        # ProcessSwitch which create many fork children doing pipe I/O.
        BENCH_RE="BM_CPUBoundUniprocess|BM_ThreadSwitch|BM_ThreadStart|BM_ProcessLifecycle"
    fi
    CMD+=(--benchmark_filter="$BENCH_RE" --benchmark_format=console --benchmark_repetitions=3 --benchmark_min_time=1s)

    echo "  CMD: ${CMD[*]}" | tee -a "$SUMMARY"

    # Capture output to a temp file first, then append to summary.
    # runsc (gVisor) writes directly to /dev/tty, bypassing shell redirects.
    # Use `script` to allocate a PTY so the output is captured properly.
    TMPOUT="$(mktemp)"
    if [[ "$MODE" == "gvisor" ]]; then
        script -q -e -c "${CMD[*]}" /dev/null >"$TMPOUT" 2>&1 || true
        # Strip carriage returns that script's PTY may add.
        sed -i 's/\r$//' "$TMPOUT"
    else
        "${CMD[@]}" >"$TMPOUT" 2>&1 || true
    fi

    # runsc (gVisor) leaves stdout in non-blocking mode, which causes
    # subsequent tee/cat calls to fail with EAGAIN ("Resource temporarily
    # unavailable").  Reset the flag after each invocation.
    python3 -c "import os,fcntl;fd=1;fl=fcntl.fcntl(fd,fcntl.F_GETFL);fcntl.fcntl(fd,fcntl.F_SETFL,fl&~os.O_NONBLOCK)" 2>/dev/null || true

    cat "$TMPOUT" | tee -a "$SUMMARY"
    rm -f "$TMPOUT"

    echo "" | tee -a "$SUMMARY"
done

echo "========================================" | tee -a "$SUMMARY"
echo "Done. [$MODE] results in: $OUTPUT_DIR" | tee -a "$SUMMARY"
echo "Summary: $SUMMARY"
