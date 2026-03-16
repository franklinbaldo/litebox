# Memcached Benchmark

Run [Memcached](https://memcached.org/) benchmarks natively and under LiteBox using [memtier_benchmark](https://github.com/redis/memtier_benchmark), then compare results.

**Why:** Memcached is a widely-used, high-performance in-memory key-value store. With `-t 1` it runs single-threaded and exercises syscalls + networking heavily. Common benchmark in OS/sandbox papers alongside Redis.

**How:** `memcached` runs inside LiteBox with smoltcp networking (via TUN device). `memtier_benchmark` drives SET/GET throughput from the host. Reports ops/sec and latency per operation type.

## Prerequisites

1. **memcached** on the host:
   ```bash
   sudo apt install memcached
   ```

2. **memtier_benchmark** — build from source (not in default apt repos):
   ```bash
   # Install build dependencies
   sudo apt install build-essential autoconf automake \
     libpcre3-dev libevent-dev pkg-config zlib1g-dev libssl-dev

   # Build memtier_benchmark
   git clone https://github.com/redis/memtier_benchmark.git
   cd memtier_benchmark
   autoreconf -ivf
   ./configure
   make
   sudo make install  # or use --memtier-path=./memtier_benchmark
   ```

3. **TUN device** set up for LiteBox networking:
   ```bash
   sudo litebox_platform_linux_userland/scripts/tun-setup.sh
   ```

4. **LiteBox binaries** (auto-built by the script unless `--no-build` is passed):
   ```bash
   cargo build --release -p litebox_runner_linux_userland -p litebox_packager
   ```

## Quick Start

```bash
# Run both native and LiteBox (default: 100k total requests, 3 iterations)
python3 dev_bench/memcached/run_memcached.py --release

# Run only native
python3 dev_bench/memcached/run_memcached.py --mode native

# Run only LiteBox
python3 dev_bench/memcached/run_memcached.py --mode litebox --release

# More iterations for stable results
python3 dev_bench/memcached/run_memcached.py --iterations 5 --release

# Custom request count and parallelism
python3 dev_bench/memcached/run_memcached.py --requests 5000 --clients 50 --threads 4 --release

# Point to locally-built memtier_benchmark
python3 dev_bench/memcached/run_memcached.py --memtier-path ~/memtier_benchmark/memtier_benchmark --release

# Save results to JSON
python3 dev_bench/memcached/run_memcached.py --release --output results.json
```

## How It Works

1. **Native:** Starts `memcached -l 127.0.0.1 -p 11212 -t 1 -m 256`, runs `memtier_benchmark` with `--protocol=memcache_text`.
2. **LiteBox:** Packages `memcached` with `litebox_packager`, starts it inside LiteBox bound to `10.0.0.2:11212` via TUN device, runs `memtier_benchmark` from host.
3. Parses JSON output from `memtier_benchmark --json-out-file` (falls back to text parse if unavailable).
4. Prints a comparison table with ops/sec, latency, and optional JSON output.

## Options

| Option             | Default       | Description |
|--------------------|---------------|-------------|
| `--mode`           | `both`        | `native`, `litebox`, or `both` |
| `--requests`       | `2000`        | Requests per client (total = requests × clients × threads) |
| `--clients`        | `25`          | Clients per memtier thread |
| `--threads`        | `2`           | memtier_benchmark threads |
| `--ratio`          | `1:10`        | SET:GET ratio |
| `--data-size`      | `32`          | Value size in bytes |
| `--key-maximum`    | `10000000`    | Key range upper bound |
| `--iterations`     | `3`           | Number of iterations |
| `--release`        | off           | Use release build of LiteBox binaries |
| `--memtier-path`   | (from PATH)   | Path to memtier_benchmark binary |
| `--port`           | `11212`       | Memcached port |
| `--tun-device`     | `tun99`       | TUN device name |
| `--output`         | (none)        | Save results to JSON file |
| `--work-dir`       | (temp)        | Working directory for intermediate files |

## Output Format

```
=========================================================================================================
Operation  Native (ops/s)  LiteBox (ops/s)    Ratio   Overhead  Native lat(ms) LiteBox lat(ms)
---------------------------------------------------------------------------------------------------------
Sets              5,000            4,200   0.8400    +16.00%           0.450           0.535
Gets             50,000           42,000   0.8400    +16.00%           0.410           0.490
Totals           55,000           46,200   0.8400    +16.00%           0.414           0.494
=========================================================================================================

Total throughput ratio (LiteBox/Native): 0.8400
Overhead: +16.00%
```

- **Ratio** = LiteBox ops/sec / Native ops/sec. Values near 1.0 mean no overhead.
- **Overhead** = percentage slowdown. Positive means LiteBox is slower.
- **Latency** = average latency in milliseconds. Lower is better.

## Networking

LiteBox uses smoltcp (a pure-Rust TCP/IP stack) over a Linux TUN device:

- **Guest IP:** `10.0.0.2` (hardcoded in LiteBox)
- **Host IP:** `10.0.0.1` (TUN interface)
- **TUN device:** `tun99` (default, configurable with `--tun-device`)

The `memtier_benchmark` client on the host connects to `10.0.0.2:11212` through the TUN device.
