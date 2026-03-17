# Node.js HTTP Server Benchmark

Run a minimal Node.js HTTP server natively and under LiteBox, then compare
request throughput and latency using [wrk](https://github.com/wg/wrk).

**Why:** Node.js is the primary sandboxing target. It exercises epoll, multiple
internal threads (libuv worker pool), and the full smoltcp networking stack.
Complements iperf3 (raw throughput) with a "real application" framing.

**How:** A tiny `http.createServer` handler returning `"Hello, World!\n"` runs
inside LiteBox with smoltcp networking (via TUN device). `wrk` drives HTTP/1.1
requests from the host. Reports requests/sec and average latency.

**Caveat:** smoltcp networking is known to be the bottleneck (shown by iperf3).
Results reflect the combined overhead of syscall interception, epoll emulation,
and the userspace TCP stack — not just the sandbox overhead in isolation.

## Prerequisites

- `node` on the host:
  ```bash
  # via nvm (recommended)
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
  nvm install --lts
  ```
- `wrk` on the host:
  ```bash
  sudo apt install wrk
  ```
- TUN device set up for LiteBox networking:
  ```bash
  sudo litebox_platform_linux_userland/scripts/tun-setup.sh
  ```
- Pre-built LiteBox binaries (auto-built by the script unless `--no-build`):
  ```bash
  cargo build --release -p litebox_runner_linux_userland -p litebox_packager
  ```

## Quick Start

```bash
# Run both native and LiteBox (default: 10s, 2 threads, 50 connections, 3 iters)
python3 dev_bench/node_http/run_node_http.py --release

# Run only LiteBox
python3 dev_bench/node_http/run_node_http.py --mode litebox --release

# Custom duration, threads, connections
python3 dev_bench/node_http/run_node_http.py --duration 15 --threads 4 --connections 100 --release

# More iterations for stable results
python3 dev_bench/node_http/run_node_http.py --iterations 5 --release

# Save results to JSON
python3 dev_bench/node_http/run_node_http.py --release --output results.json
```

## Example Output

```
[Native] Node.js HTTP (x3 iterations)
  Iteration 1/3
    45,321 req/s, avg latency 1.10ms
  Iteration 2/3
    46,012 req/s, avg latency 1.08ms
  Iteration 3/3
    45,876 req/s, avg latency 1.09ms
[LiteBox] Node.js HTTP (x3 iterations)
  Iteration 1/3
    2,345 req/s, avg latency 21.32ms
  ...

==========================================================================================
Metric                          Native          LiteBox    Ratio   Overhead
------------------------------------------------------------------------------------------
Requests/sec                    45,736            2,345   0.0513    +94.87%
Avg Latency                    1.09ms          21.32ms   19.5596
==========================================================================================
```
