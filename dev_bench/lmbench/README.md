# LMbench Benchmark Scripts

Run [LMbench](https://github.com/intel/lmbench) benchmarks natively and under LiteBox, then compare results.

LMbench is a suite of portable benchmarks for measuring key system performance metrics including latency (system calls, signals, context switches, process creation) and bandwidth (memory, pipes, unix sockets).

## Prerequisites

- `gcc`, `make`, `ldd`, `tar` on the host.
- Pre-built LiteBox binaries (for LiteBox mode):

```bash
cargo build --release -p litebox_runner_linux_userland -p litebox_packager
```

> **Note:** On some systems you may need `libtirpc-dev` (or similar) if the LMbench build complains about missing `rpc/rpc.h` headers. Core benchmarks should still build without it.

## Quick Start

```bash
# Run all benchmarks natively
python3 dev_bench/lmbench/run_lmbench.py

# Run specific benchmarks
python3 dev_bench/lmbench/run_lmbench.py --benchmarks lat_syscall_null lat_pipe bw_pipe

# Override repetitions (-N flag to lmbench)
python3 dev_bench/lmbench/run_lmbench.py --repetitions 3

# Run multiple iterations for averaging
python3 dev_bench/lmbench/run_lmbench.py --iterations 3

# Save results to JSON
python3 dev_bench/lmbench/run_lmbench.py --output results.json
```

## Supported Benchmarks

### Latency Benchmarks (lower is better)

| Benchmark | Binary | Description |
|---|---|---|
| `lat_syscall_null` | lat_syscall | getppid() latency |
| `lat_syscall_read` | lat_syscall | read /dev/zero latency |
| `lat_syscall_write` | lat_syscall | write /dev/null latency |
| `lat_syscall_stat` | lat_syscall | stat() latency |
| `lat_syscall_fstat` | lat_syscall | fstat() latency |
| `lat_syscall_open` | lat_syscall | open/close latency |
| `lat_sig_install` | lat_sig | signal handler install latency |
| `lat_sig_catch` | lat_sig | signal catch latency |
| `lat_sig_prot` | lat_sig | protection fault latency |
| `lat_pipe` | lat_pipe | pipe round-trip latency |
| `lat_proc_fork` | lat_proc | fork+exit latency |
| `lat_proc_exec` | lat_proc | fork+exec latency |
| `lat_proc_shell` | lat_proc | fork+/bin/sh latency |
| `lat_ctx` | lat_ctx | context switch latency (2 procs, 0K) |

### Bandwidth Benchmarks (higher is better)

| Benchmark | Binary | Description |
|---|---|---|
| `bw_mem_rd` | bw_mem | memory read bandwidth (512K) |
| `bw_mem_wr` | bw_mem | memory write bandwidth (512K) |
| `bw_mem_cp` | bw_mem | memory copy bandwidth (512K) |
| `bw_mem_bzero` | bw_mem | memory bzero bandwidth (512K) |
| `bw_pipe` | bw_pipe | pipe bandwidth |
| `bw_unix` | bw_unix | unix socket bandwidth |

### Note on Fork Requirement

All LMbench3 benchmarks use the `benchmp()` timing framework, which internally uses `fork()` to create measurement processes. This means **all benchmarks require fork support** to run under LiteBox.

Currently, the default mode is `--mode native` (native-only). When fork support is available in LiteBox, you can use `--mode both` to compare native vs LiteBox performance.

## Output Format

### Native-only mode (default)

```
============================================================
Benchmark                 Unit          Value  Description
------------------------------------------------------------
lat_syscall_null          usec        0.0714  getppid() latency
lat_syscall_read          usec        0.0900  read /dev/zero latency
lat_pipe                  usec        5.4200  pipe round-trip latency
bw_mem_rd                 MB/sec   8234.5600  memory read bandwidth (512K)
============================================================
```

### Comparison mode (`--mode both`)

```
==========================================================================================
Benchmark                 Unit          Native      LiteBox    Ratio   Overhead
------------------------------------------------------------------------------------------
lat_syscall_null          usec        0.0714       0.0800   1.1204     12.04%
bw_mem_rd                 MB/sec   8234.5600    7800.0000   0.9473      5.27%
==========================================================================================
```

## JSON Output

Use `--output results.json` to get machine-readable results:

```json
{
  "config": { "repetitions_override": null, "iterations": 1, ... },
  "results": {
    "lat_syscall_null": {
      "unit": "usec",
      "higher_is_better": false,
      "native_values": [0.0714],
      "litebox_values": [],
      "native_avg": 0.0714,
      "litebox_avg": null,
      "ratio": null,
      "overhead_pct": null
    },
    ...
  }
}
```

## How It Works

1. **Download**: LMbench source is downloaded from GitHub (`master` branch).
2. **Build**: `make` is run in the `src/` directory. Binaries go to `bin/<os>/`.
3. **Run**: Each benchmark is executed with `-N <repetitions>` to control measurement count.
4. **Parse**: Output is parsed from stderr (LMbench writes results to stderr by default).
5. **Compare**: Results are tabulated with native vs LiteBox comparison when applicable.

## Preparing for Windows

```bash
# Prepare all benchmarks on Linux
python3 dev_bench/lmbench/prepare_lmbench.py --release

# Prepare specific benchmarks
python3 dev_bench/lmbench/prepare_lmbench.py --benchmarks lat_syscall_null bw_pipe --release
```

This creates `dev_bench/lmbench/prepared/` with per-benchmark directories containing rewritten binaries and rootfs tars.
