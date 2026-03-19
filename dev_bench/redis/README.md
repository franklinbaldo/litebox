# Redis Benchmark

Run [Redis](https://redis.io/) benchmarks natively and under LiteBox, then compare results.

**Why:** Directly comparable to Asterinas (1.31×) and gVisor (~1.5–2× with KVM). Redis is single-process, in-memory, and exercises syscalls + networking heavily. Extremely common benchmark in OS/sandbox papers.

**How:** `redis-server` runs inside LiteBox with smoltcp networking (via TUN device). `redis-benchmark` drives SET/GET throughput from the host. Reports ops/sec per test.

**Caveat:** Redis forks for persistence (`BGSAVE`), but is configured to run entirely without it (`save ""`, `appendonly no`) to avoid fork syscalls.

## Prerequisites

- `redis-server` and `redis-benchmark` on the host:
  ```bash
  sudo apt install redis-server redis-tools
  ```
- TUN device set up for LiteBox networking:
  ```bash
  sudo litebox_platform_linux_userland/scripts/tun-setup.sh
  ```
- Pre-built LiteBox binaries (auto-built by the script unless `--no-build` is passed):
  ```bash
  cargo build --release -p litebox_runner_linux_userland -p litebox_packager
  ```

## Quick Start

```bash
# Run both native and LiteBox (default: 100k requests, 50 clients, 3 iterations)
python3 dev_bench/redis/run_redis.py --release

# Run only native
python3 dev_bench/redis/run_redis.py --mode native

# Run only LiteBox
python3 dev_bench/redis/run_redis.py --mode litebox --release

# More iterations for stable results
python3 dev_bench/redis/run_redis.py --iterations 5 --release

# Custom request count and parallelism
python3 dev_bench/redis/run_redis.py --requests 200000 --clients 20 --release

# Specific tests only
python3 dev_bench/redis/run_redis.py --tests SET GET --release

# Save results to JSON
python3 dev_bench/redis/run_redis.py --release --output results.json
```

## How It Works

1. Writes a minimal `redis.conf` (no persistence, no fork, no protected mode).
2. **Native:** Starts `redis-server` on `127.0.0.1:6399`, runs `redis-benchmark --csv`.
3. **LiteBox:** Packages `redis-server` + config with `litebox_packager`, starts it inside LiteBox bound to `10.0.0.2:6399` via TUN device, runs `redis-benchmark --csv` from host.
4. Parses CSV output for per-test ops/sec.
5. Prints a comparison table and optional JSON output.

## Default Tests

| Test | Description |
|------|-------------|
| SET | String SET |
| GET | String GET |
| INCR | Integer increment |
| LPUSH | List push (left) |
| RPUSH | List push (right) |
| LPOP | List pop (left) |
| RPOP | List pop (right) |
| SADD | Set add |
| HSET | Hash set |
| MSET | Multi-key string set (10 keys) |

## Output Format

```
=====================================================================================
Test            Native (ops/s)  LiteBox (ops/s)    Ratio   Overhead
-------------------------------------------------------------------------------------
SET                    120,000           95,000   0.7917    +20.83%
GET                    130,000          105,000   0.8077    +19.23%
...
=====================================================================================

Geometric mean throughput ratio (LiteBox/Native): 0.7996
Overhead: +20.04%
```

- **Ratio** = LiteBox ops/sec / Native ops/sec. Values near 1.0 mean no overhead.
- **Overhead** = percentage slowdown. Positive means LiteBox is slower.

## Networking

LiteBox uses smoltcp (a pure-Rust TCP/IP stack) over a Linux TUN device:

- **Guest IP:** `10.0.0.2` (hardcoded in LiteBox)
- **Host IP:** `10.0.0.1` (TUN interface)
- **TUN device:** `tun99` (default, configurable with `--tun-device`)

The `redis-benchmark` client on the host connects to `10.0.0.2:6399` through the TUN device.

## Options

| Flag | Default | Description |
|---|---|---|
| `--mode {both,native,litebox}` | `both` | Which runs to perform |
| `--requests N` | `100000` | Number of requests per test |
| `--clients N` | `50` | Number of parallel clients |
| `--tests TEST [TEST ...]` | all 10 | Which tests to run |
| `--iterations N` | `3` | Number of iterations per mode |
| `--release` | (off) | Use release build of LiteBox binaries |
| `--port N` | `6399` | Redis server port |
| `--tun-device NAME` | `tun99` | TUN device for LiteBox networking |
| `--runner-path PATH` | (auto) | Path to `litebox_runner_linux_userland` |
| `--packager-path PATH` | (auto) | Path to `litebox_packager` |
| `--no-build` | (off) | Skip building LiteBox binaries |
| `--output FILE` | (none) | Save results to JSON |
| `--work-dir DIR` | (temp) | Working directory for intermediate files |
