#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Run Memcached benchmarks natively and under LiteBox, then compare results.

Memcached is a high-performance, in-memory key-value store. With -t 1 it runs
single-threaded, exercising syscalls + networking heavily.
memtier_benchmark (https://github.com/redis/memtier_benchmark) from outside
drives SET/GET throughput (ops/sec) and measures latencies.

Prerequisites:
  - memcached installed on host (sudo apt install memcached)
  - memtier_benchmark installed on host (build from source, see README.md)
  - For LiteBox mode: TUN device set up (see litebox_platform_linux_userland/scripts/tun-setup.sh)

Usage:
    python3 run_memcached.py [options]

Examples:
    # Run both native and LiteBox (default: 100k total requests, 3 iterations)
    python3 run_memcached.py --release

    # Run only native
    python3 run_memcached.py --mode native

    # Run only LiteBox
    python3 run_memcached.py --mode litebox --release

    # Override request count and client count
    python3 run_memcached.py --requests 200000 --clients 25 --release

    # More iterations for stable results
    python3 run_memcached.py --iterations 5 --release

    # Save results to JSON
    python3 run_memcached.py --release --output results.json
"""

import argparse
import json
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Constants ───────────────────────────────────────────────────────────────

GUEST_IP = "10.0.0.2"
MEMCACHED_PORT = 11212  # non-default port to avoid conflict with host memcached
TUN_DEVICE = "tun99"

# Default memtier_benchmark parameters:
#   total requests = requests_per_client * clients * threads
# With defaults: 2000 * 4 * 2 = 16,000
DEFAULT_REQUESTS_PER_CLIENT = 2000
DEFAULT_CLIENTS = 4
DEFAULT_THREADS = 2
DEFAULT_RATIO = "1:10"  # SET:GET ratio
DEFAULT_DATA_SIZE = 32  # value size in bytes
DEFAULT_KEY_MAX = 10000000

# Operation types reported by memtier_benchmark
OP_TYPES = ["Sets", "Gets", "Totals"]


# ── Workspace helpers ───────────────────────────────────────────────────────


def find_workspace_root() -> Path:
    """Find the workspace root (directory containing Cargo.toml with [workspace])."""
    script_dir = Path(__file__).resolve().parent
    candidate = script_dir
    while candidate != candidate.parent:
        cargo_toml = candidate / "Cargo.toml"
        if cargo_toml.exists():
            content = cargo_toml.read_text()
            if "[workspace]" in content:
                return candidate
        candidate = candidate.parent
    print("Error: could not find workspace root")
    sys.exit(1)


def locate_command(name: str) -> Optional[Path]:
    """Find a command on PATH."""
    result = shutil.which(name)
    return Path(result) if result else None


# ── Result Parsing ──────────────────────────────────────────────────────────


@dataclass
class OpResult:
    """Result for a single operation type (e.g. Sets, Gets, Totals)."""

    name: str
    ops_per_sec: float
    avg_latency_ms: float
    p50_latency_ms: float
    p99_latency_ms: float
    p999_latency_ms: float
    kb_per_sec: float


@dataclass
class BenchmarkResult:
    """Parsed results from a single memtier_benchmark run."""

    ops: list[OpResult]
    elapsed: float  # wall-clock seconds
    raw_output: str = ""

    @property
    def total_ops_per_sec(self) -> Optional[float]:
        for op in self.ops:
            if op.name == "Totals":
                return op.ops_per_sec
        return None

    def to_dict(self) -> dict:
        return {
            "elapsed": self.elapsed,
            "ops": {
                op.name: {
                    "ops_per_sec": op.ops_per_sec,
                    "avg_latency_ms": op.avg_latency_ms,
                    "p99_latency_ms": op.p99_latency_ms,
                }
                for op in self.ops
            },
        }


def parse_memtier_json(json_path: Path) -> list[OpResult]:
    """
    Parse memtier_benchmark --json-out-file output.

    JSON structure:
    {
        "ALL STATS": {
            "Sets": { "Ops/sec": ..., "Average Latency": ..., ... },
            "Gets": { "Ops/sec": ..., ... },
            "Totals": { "Ops/sec": ..., ... }
        }
    }
    """
    with open(json_path) as f:
        data = json.load(f)

    all_stats = data.get("ALL STATS", {})
    results = []
    for op_name in OP_TYPES:
        stats = all_stats.get(op_name)
        if stats is None:
            continue

        pct = stats.get("Percentile Latencies", {})
        results.append(
            OpResult(
                name=op_name,
                ops_per_sec=stats.get("Ops/sec", 0.0),
                avg_latency_ms=stats.get("Average Latency", 0.0),
                p50_latency_ms=pct.get("p50.00", 0.0),
                p99_latency_ms=pct.get("p99.00", 0.0),
                p999_latency_ms=pct.get("p99.90", 0.0),
                kb_per_sec=stats.get("KB/sec", 0.0),
            )
        )
    return results


def parse_memtier_text(output: str) -> list[OpResult]:
    """
    Fallback parser for memtier_benchmark text output.

    Table looks like:
    Type         Ops/sec     Hits/sec   Misses/sec    Avg. Latency ...
    ------...
    Sets        50000.23          ---          ---         0.50123 ...
    Gets        50000.23     45000.02      5000.21         0.48200 ...
    Waits           0.00          ---          ---             --- ...
    Totals     100000.45     45000.02      5000.21         0.49162 ...
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        for op_name in OP_TYPES:
            if line.startswith(op_name):
                parts = line.split()
                if len(parts) < 5:
                    continue
                try:
                    ops_sec = float(parts[1])
                except (ValueError, IndexError):
                    continue
                # Parse latency columns - positions may vary
                avg_lat = 0.0
                p50_lat = 0.0
                p99_lat = 0.0
                p999_lat = 0.0
                kb_sec = 0.0
                try:
                    avg_lat = float(parts[4]) if parts[4] != "---" else 0.0
                except (ValueError, IndexError):
                    pass
                try:
                    p50_lat = float(parts[5]) if parts[5] != "---" else 0.0
                except (ValueError, IndexError):
                    pass
                try:
                    p99_lat = float(parts[6]) if parts[6] != "---" else 0.0
                except (ValueError, IndexError):
                    pass
                try:
                    p999_lat = float(parts[7]) if parts[7] != "---" else 0.0
                except (ValueError, IndexError):
                    pass
                try:
                    kb_sec = float(parts[8]) if parts[8] != "---" else 0.0
                except (ValueError, IndexError):
                    pass
                results.append(
                    OpResult(
                        name=op_name,
                        ops_per_sec=ops_sec,
                        avg_latency_ms=avg_lat,
                        p50_latency_ms=p50_lat,
                        p99_latency_ms=p99_lat,
                        p999_latency_ms=p999_lat,
                        kb_per_sec=kb_sec,
                    )
                )
    return results


# ── Server Management ───────────────────────────────────────────────────────


def wait_for_memcached(
    host: str,
    port: int,
    timeout: float = 30.0,
    proc: Optional[subprocess.Popen] = None,
) -> bool:
    """Wait until memcached is accepting connections via TCP connect.

    If *proc* is given, also checks whether the server process has already
    exited (e.g. crashed on startup) so we don't wait the full timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # Early exit: server process already terminated
        if proc is not None and proc.poll() is not None:
            return False
        try:
            s = socket.create_connection((host, port), timeout=2.0)
            # Connection accepted — server is listening.
            # Try to get a version response, but don't require it:
            # under LiteBox's smoltcp networking the first response
            # may arrive after a small delay.
            try:
                s.sendall(b"version\r\n")
                s.settimeout(1.0)
                data = s.recv(256)
            except OSError:
                data = b""
            s.close()
            if data and b"VERSION" in data:
                return True
            # Connection succeeded but no version response yet — give
            # the event loop a moment and try once more.
            time.sleep(0.3)
            try:
                s2 = socket.create_connection((host, port), timeout=2.0)
                s2.sendall(b"version\r\n")
                s2.settimeout(2.0)
                data2 = s2.recv(256)
                s2.close()
                # Accept if we got any data or even if empty — the TCP
                # accept itself proves memcached is running.
                return True
            except OSError:
                # TCP connect worked before but not now — keep trying.
                pass
        except OSError:
            pass
        time.sleep(0.2)
    return False


# ── Native Runner ───────────────────────────────────────────────────────────


def run_native(
    requests_per_client: int,
    clients: int,
    threads: int,
    ratio: str,
    data_size: int,
    key_max: int,
    work_dir: Path,
    memtier_path: Path,
) -> Optional[BenchmarkResult]:
    """Run memcached natively and benchmark it."""
    memcached = locate_command("memcached")
    if memcached is None:
        print("  [SKIP] memcached not found on PATH")
        return None

    # Start memcached: single-threaded, bind to loopback, non-default port
    server_cmd = [
        str(memcached),
        "-l", "127.0.0.1",
        "-p", str(MEMCACHED_PORT),
        "-t", "1",         # single thread for fair comparison
        "-m", "256",       # 256 MB memory limit
        "-c", "1024",      # max connections
    ]
    # -u is required when running as root
    if os.getuid() == 0:
        server_cmd += ["-u", "nobody"]
    print(f"  Starting: {' '.join(server_cmd)}")
    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        print("  Waiting for native memcached...")
        if not wait_for_memcached("127.0.0.1", MEMCACHED_PORT):
            print("  [FAIL] memcached did not start in time")
            stderr = server_proc.stderr.read().decode("utf-8", errors="replace")
            if stderr:
                print(f"  stderr: {stderr[:500]}")
            return None

        # Run memtier_benchmark
        json_out = work_dir / "memtier_native.json"
        cmd = [
            str(memtier_path),
            "-s", "127.0.0.1",
            "-p", str(MEMCACHED_PORT),
            "--protocol=memcache_text",
            "-n", str(requests_per_client),
            "-c", str(clients),
            "-t", str(threads),
            f"--ratio={ratio}",
            f"--data-size={data_size}",
            "--key-minimum=1",
            f"--key-maximum={key_max}",
            f"--json-out-file={json_out}",
        ]
        print(f"  Running: {' '.join(cmd)}")
        t0 = time.monotonic()
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("  [TIMEOUT]")
            return None
        elapsed = time.monotonic() - t0

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        if result.returncode != 0:
            print(f"  [FAIL] memtier_benchmark exit code {result.returncode}")
            print(f"  stderr: {stderr[:500]}")
            return None

        # Parse JSON output (preferred), fall back to text
        if json_out.exists():
            op_results = parse_memtier_json(json_out)
        else:
            op_results = parse_memtier_text(stdout)

        if not op_results:
            print(f"  [FAIL] no results parsed from output:\n{stdout[:500]}")
            return None

        return BenchmarkResult(
            ops=op_results,
            elapsed=elapsed,
            raw_output=stdout,
        )
    finally:
        # Shutdown memcached (SIGTERM is the clean way)
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait()


# ── LiteBox Runner ──────────────────────────────────────────────────────────


def _extract_rewritten_binary(
    tar_path: Path,
    original_binary: Path,
    output_path: Path,
) -> None:
    """Extract the rewritten main binary from the packager tar."""
    binary_name = original_binary.name
    with tarfile.open(tar_path, "r") as tf:
        for member in tf.getmembers():
            if member.name.endswith(f"/{binary_name}") or member.name == binary_name:
                f = tf.extractfile(member)
                if f is None:
                    continue
                output_path.write_bytes(f.read())
                output_path.chmod(0o755)
                return
    raise RuntimeError(
        f"Could not find rewritten '{binary_name}' in {tar_path}"
    )


def prepare_litebox_rootfs(
    memcached_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[tuple[Path, Path]]:
    """Prepare rootfs tar for LiteBox using litebox_packager."""
    tar_path = work_dir / "rootfs_memcached.tar"
    rewritten = work_dir / "memcached.hooked"

    # Reuse if already prepared
    if tar_path.exists() and rewritten.exists():
        return tar_path, rewritten

    if packager_path:
        cmd = [str(packager_path)]
    else:
        cmd = ["cargo", "run", "-p", "litebox_packager", "--"]

    cmd += [
        str(memcached_path),
        "-o", str(tar_path),
    ]

    print("  Packaging with litebox_packager...")
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Error: packager failed: {stderr[:500]}")
        return None

    try:
        _extract_rewritten_binary(tar_path, memcached_path, rewritten)
    except RuntimeError as e:
        print(f"  Error: {e}")
        return None

    return tar_path, rewritten


def run_litebox(
    requests_per_client: int,
    clients: int,
    threads: int,
    ratio: str,
    data_size: int,
    key_max: int,
    runner_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
    memtier_path: Path,
) -> Optional[BenchmarkResult]:
    """Run memcached under LiteBox and benchmark from host."""
    memcached = locate_command("memcached")
    if memcached is None:
        print("  [SKIP] memcached not found on PATH")
        return None

    prepared = prepare_litebox_rootfs(memcached, work_dir, packager_path)
    if prepared is None:
        return None

    tar_path, rewritten = prepared

    # Start memcached inside LiteBox
    server_cmd = [
        str(runner_path),
        "--unstable",
        "--interception-backend", "rewriter",
        "--env", "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
        "--env", "HOME=/",
    ]
    server_cmd += [
        "--tun-device-name", TUN_DEVICE,
        "--initial-files", str(tar_path),
        str(rewritten),
        "-l", GUEST_IP,
        "-p", str(MEMCACHED_PORT),
        "-t", "1",
        "-m", "256",
        "-c", "1024",
    ]

    print(f"  Starting LiteBox memcached:\n    {' '.join(server_cmd)}")
    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        print(f"  Waiting for memcached at {GUEST_IP}:{MEMCACHED_PORT}...")
        if not wait_for_memcached(GUEST_IP, MEMCACHED_PORT, timeout=60.0, proc=server_proc):
            stderr = ""
            stdout = ""
            try:
                stdout_bytes, stderr_bytes = server_proc.communicate(timeout=2)
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                stdout = stdout_bytes.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                pass
            rc = server_proc.poll()
            if rc is not None:
                print(f"  [FAIL] LiteBox server exited early (code {rc})")
            else:
                print("  [FAIL] LiteBox memcached did not start in time")
            if stderr:
                print(f"  stderr (last 500): ...{stderr[-500:]}")
            if stdout:
                print(f"  stdout (last 500): ...{stdout[-500:]}")
            return None

        # Run memtier_benchmark from host side
        json_out = work_dir / "memtier_litebox.json"
        cmd = [
            str(memtier_path),
            "-s", GUEST_IP,
            "-p", str(MEMCACHED_PORT),
            "--protocol=memcache_text",
            "-n", str(requests_per_client),
            "-c", str(clients),
            "-t", str(threads),
            f"--ratio={ratio}",
            f"--data-size={data_size}",
            "--key-minimum=1",
            f"--key-maximum={key_max}",
            f"--json-out-file={json_out}",
        ]
        print(f"  Running: {' '.join(cmd)}")
        t0 = time.monotonic()
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("  [TIMEOUT]")
            return None
        elapsed = time.monotonic() - t0

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        if result.returncode != 0:
            print(f"  [FAIL] memtier_benchmark exit code {result.returncode}")
            print(f"  stderr: {stderr[:500]}")
            return None

        # Parse JSON output (preferred), fall back to text
        if json_out.exists():
            op_results = parse_memtier_json(json_out)
        else:
            op_results = parse_memtier_text(stdout)

        if not op_results:
            print(f"  [FAIL] no results parsed from output:\n{stdout[:500]}")
            return None

        return BenchmarkResult(
            ops=op_results,
            elapsed=elapsed,
            raw_output=stdout,
        )
    finally:
        # Shutdown memcached (SIGTERM)
        server_proc.terminate()
        try:
            server_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait()


# ── Comparison & Reporting ──────────────────────────────────────────────────


@dataclass
class ComparisonRow:
    name: str
    native_ops: list[float] = field(default_factory=list)
    litebox_ops: list[float] = field(default_factory=list)
    native_lat: list[float] = field(default_factory=list)
    litebox_lat: list[float] = field(default_factory=list)

    @property
    def native_avg_ops(self) -> Optional[float]:
        return sum(self.native_ops) / len(self.native_ops) if self.native_ops else None

    @property
    def litebox_avg_ops(self) -> Optional[float]:
        return sum(self.litebox_ops) / len(self.litebox_ops) if self.litebox_ops else None

    @property
    def native_avg_lat(self) -> Optional[float]:
        return sum(self.native_lat) / len(self.native_lat) if self.native_lat else None

    @property
    def litebox_avg_lat(self) -> Optional[float]:
        return sum(self.litebox_lat) / len(self.litebox_lat) if self.litebox_lat else None

    @property
    def overhead_pct(self) -> Optional[float]:
        """Overhead %. Positive means LiteBox is slower (lower ops/sec)."""
        n = self.native_avg_ops
        lb = self.litebox_avg_ops
        if n and lb and n > 0:
            return ((n - lb) / n) * 100.0
        return None

    @property
    def ratio(self) -> Optional[float]:
        """Throughput ratio (LiteBox / Native). Values near 1.0 = no overhead."""
        n = self.native_avg_ops
        lb = self.litebox_avg_ops
        if n and lb and n > 0:
            return lb / n
        return None


def print_comparison_table(rows: list[ComparisonRow]):
    """Print formatted comparison table (higher ops/sec is better)."""
    print()
    print("=" * 105)
    print(
        f"{'Operation':<10} {'Native (ops/s)':>16} {'LiteBox (ops/s)':>16}"
        f" {'Ratio':>8} {'Overhead':>10}"
        f" {'Native lat(ms)':>15} {'LiteBox lat(ms)':>16}"
    )
    print("-" * 105)

    for row in rows:
        native_str = f"{row.native_avg_ops:,.0f}" if row.native_avg_ops is not None else "N/A"
        litebox_str = f"{row.litebox_avg_ops:,.0f}" if row.litebox_avg_ops is not None else "N/A"
        ratio_str = f"{row.ratio:.4f}" if row.ratio is not None else "N/A"
        overhead_str = f"{row.overhead_pct:+.2f}%" if row.overhead_pct is not None else "N/A"
        native_lat_str = f"{row.native_avg_lat:.3f}" if row.native_avg_lat is not None else "N/A"
        litebox_lat_str = f"{row.litebox_avg_lat:.3f}" if row.litebox_avg_lat is not None else "N/A"
        print(
            f"{row.name:<10} {native_str:>16} {litebox_str:>16}"
            f" {ratio_str:>8} {overhead_str:>10}"
            f" {native_lat_str:>15} {litebox_lat_str:>16}"
        )

    print("=" * 105)

    # Compute geometric mean from Totals row only
    totals = [r for r in rows if r.name == "Totals"]
    if totals and totals[0].ratio is not None:
        print(f"\nTotal throughput ratio (LiteBox/Native): {totals[0].ratio:.4f}")
        print(f"Overhead: {totals[0].overhead_pct:+.2f}%")
    else:
        ratios = [r.ratio for r in rows if r.ratio is not None]
        if ratios:
            geo_mean = math.prod(ratios) ** (1.0 / len(ratios))
            print(f"\nGeometric mean throughput ratio (LiteBox/Native): {geo_mean:.4f}")
            print(f"Overhead: {(1.0 - geo_mean) * 100:+.2f}%")
    print()


# ── Build helpers ───────────────────────────────────────────────────────────


def build_litebox_binaries(
    workspace_root: Path,
    release: bool,
) -> tuple[Path, Path]:
    """Build litebox runner and packager."""
    build_type = "release" if release else "debug"
    cmd = [
        "cargo", "build",
        "-p", "litebox_runner_linux_userland",
        "-p", "litebox_packager",
    ]
    if release:
        cmd.append("--release")

    print(f"Building litebox binaries ({build_type})...")
    result = subprocess.run(cmd, cwd=str(workspace_root))
    if result.returncode != 0:
        print(f"Error: cargo build failed (exit {result.returncode})")
        sys.exit(1)
    print("Build complete.")

    runner = workspace_root / "target" / build_type / "litebox_runner_linux_userland"
    packager = workspace_root / "target" / build_type / "litebox_packager"
    assert runner.exists(), f"Runner not found at {runner}"
    assert packager.exists(), f"Packager not found at {packager}"
    return runner, packager


def find_litebox_binaries(
    workspace_root: Path,
    release: bool,
) -> tuple[Optional[Path], Optional[Path]]:
    """Find pre-built litebox binaries."""
    build_type = "release" if release else "debug"
    runner = workspace_root / "target" / build_type / "litebox_runner_linux_userland"
    packager = workspace_root / "target" / build_type / "litebox_packager"
    return (
        runner if runner.exists() else None,
        packager if packager.exists() else None,
    )


def check_tun_device() -> bool:
    """Check if the TUN device exists."""
    result = subprocess.run(
        ["ip", "tuntap", "show"],
        capture_output=True,
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    return f"{TUN_DEVICE}:" in stdout


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    global TUN_DEVICE, MEMCACHED_PORT
    parser = argparse.ArgumentParser(
        description="Run Memcached benchmarks natively and under LiteBox.",
    )
    parser.add_argument(
        "--mode",
        choices=["both", "native", "litebox"],
        default="both",
        help="Run mode (default: both)",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=DEFAULT_REQUESTS_PER_CLIENT,
        help=f"Requests per client (default: {DEFAULT_REQUESTS_PER_CLIENT}, "
        f"total = requests * clients * threads)",
    )
    parser.add_argument(
        "--clients",
        type=int,
        default=DEFAULT_CLIENTS,
        help=f"Clients per thread (default: {DEFAULT_CLIENTS})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Memtier client threads (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--ratio",
        type=str,
        default=DEFAULT_RATIO,
        help=f"SET:GET ratio (default: {DEFAULT_RATIO})",
    )
    parser.add_argument(
        "--data-size",
        type=int,
        default=DEFAULT_DATA_SIZE,
        help=f"Value size in bytes (default: {DEFAULT_DATA_SIZE})",
    )
    parser.add_argument(
        "--key-maximum",
        type=int,
        default=DEFAULT_KEY_MAX,
        help=f"Max key range (default: {DEFAULT_KEY_MAX})",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of iterations (default: 3)",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="Use release build of litebox binaries",
    )
    parser.add_argument(
        "--runner-path",
        type=str,
        default=None,
        help="Path to litebox_runner_linux_userland binary",
    )
    parser.add_argument(
        "--packager-path",
        type=str,
        default=None,
        help="Path to litebox_packager binary",
    )
    parser.add_argument(
        "--memtier-path",
        type=str,
        default=None,
        help="Path to memtier_benchmark binary",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip building litebox binaries",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Save results to JSON file",
    )
    parser.add_argument(
        "--work-dir",
        type=str,
        default=None,
        help="Working directory for intermediate files",
    )
    parser.add_argument(
        "--tun-device",
        type=str,
        default=TUN_DEVICE,
        help=f"TUN device name (default: {TUN_DEVICE})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=MEMCACHED_PORT,
        help=f"Memcached port (default: {MEMCACHED_PORT})",
    )

    args = parser.parse_args()

    TUN_DEVICE = args.tun_device
    MEMCACHED_PORT = args.port

    # Check prerequisites
    if locate_command("memcached") is None:
        print("Error: memcached not found on PATH.")
        print("Install it: sudo apt install memcached")
        sys.exit(1)

    # Resolve memtier_benchmark
    if args.memtier_path:
        memtier_path = Path(args.memtier_path)
        if not memtier_path.exists():
            print(f"Error: memtier_benchmark not found at {memtier_path}")
            sys.exit(1)
    else:
        memtier_path = locate_command("memtier_benchmark")
        if memtier_path is None:
            print("Error: memtier_benchmark not found on PATH.")
            print("Build from source:")
            print("  sudo apt install build-essential autoconf automake \\")
            print("    libpcre3-dev libevent-dev pkg-config zlib1g-dev libssl-dev")
            print("  git clone https://github.com/redis/memtier_benchmark.git")
            print("  cd memtier_benchmark && autoreconf -ivf && ./configure && make")
            print("  sudo make install  # or pass --memtier-path=./memtier_benchmark")
            sys.exit(1)

    workspace_root = find_workspace_root()

    # Resolve litebox binaries
    run_litebox_mode = args.mode in ("both", "litebox")
    runner_path = None
    packager_path = None

    if run_litebox_mode:
        # Check TUN device
        if not check_tun_device():
            print(f"Error: TUN device '{TUN_DEVICE}' not found.")
            print("Set it up with:")
            print(f"  sudo litebox_platform_linux_userland/scripts/tun-setup.sh -t {TUN_DEVICE}")
            sys.exit(1)

        if args.runner_path:
            runner_path = Path(args.runner_path)
            if args.packager_path:
                packager_path = Path(args.packager_path)
        elif args.no_build:
            runner_path, packager_path = find_litebox_binaries(
                workspace_root, args.release,
            )
            if runner_path is None:
                print("Error: litebox_runner_linux_userland not found.")
                print(
                    "Run without --no-build, or build manually:\n"
                    "  cargo build -p litebox_runner_linux_userland"
                    + (" --release" if args.release else "")
                )
                sys.exit(1)
        else:
            runner_path, packager_path = build_litebox_binaries(
                workspace_root, args.release,
            )

    # Working directory
    if args.work_dir:
        work_dir = Path(args.work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        cleanup_work_dir = False
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="litebox_memcached_bench_"))
        cleanup_work_dir = True

    total_reqs = args.requests * args.clients * args.threads
    print(f"Workspace root: {workspace_root}")
    print(f"Work dir:       {work_dir}")
    print(f"Requests/client:{args.requests}")
    print(f"Clients/thread: {args.clients}")
    print(f"Threads:        {args.threads}")
    print(f"Total requests: {total_reqs:,}")
    print(f"Ratio (S:G):    {args.ratio}")
    print(f"Data size:      {args.data_size} bytes")
    print(f"Iterations:     {args.iterations}")
    print(f"Mode:           {args.mode}")
    print(f"Port:           {MEMCACHED_PORT}")
    print(f"memtier:        {memtier_path}")
    if run_litebox_mode:
        print(f"TUN device:     {TUN_DEVICE}")
        print(f"Runner:         {runner_path}")
        print(f"Packager:       {packager_path or 'cargo run'}")
    print()

    # Per-operation comparison rows
    all_rows: dict[str, ComparisonRow] = {
        t: ComparisonRow(name=t) for t in OP_TYPES
    }

    # ── Native runs ─────────────────────────────────────────────────────

    if args.mode in ("both", "native"):
        print(f"[Native] Memcached benchmark (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_native(
                args.requests, args.clients, args.threads,
                args.ratio, args.data_size, args.key_maximum,
                work_dir, memtier_path,
            )
            if result:
                for op in result.ops:
                    if op.name in all_rows:
                        all_rows[op.name].native_ops.append(op.ops_per_sec)
                        all_rows[op.name].native_lat.append(op.avg_latency_ms)
                        print(
                            f"    {op.name}: {op.ops_per_sec:,.0f} ops/sec "
                            f"(avg lat {op.avg_latency_ms:.3f} ms)"
                        )

    # ── LiteBox runs ────────────────────────────────────────────────────

    if run_litebox_mode:
        print(f"[LiteBox] Memcached benchmark (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_litebox(
                args.requests, args.clients, args.threads,
                args.ratio, args.data_size, args.key_maximum,
                runner_path, work_dir, packager_path, memtier_path,
            )
            if result:
                for op in result.ops:
                    if op.name in all_rows:
                        all_rows[op.name].litebox_ops.append(op.ops_per_sec)
                        all_rows[op.name].litebox_lat.append(op.avg_latency_ms)
                        print(
                            f"    {op.name}: {op.ops_per_sec:,.0f} ops/sec "
                            f"(avg lat {op.avg_latency_ms:.3f} ms)"
                        )

    # ── Results ─────────────────────────────────────────────────────────

    rows = [all_rows[t] for t in OP_TYPES if t in all_rows]
    print_comparison_table(rows)

    # ── Save to JSON ────────────────────────────────────────────────────

    if args.output:
        output_data = {
            "config": {
                "requests_per_client": args.requests,
                "clients": args.clients,
                "threads": args.threads,
                "ratio": args.ratio,
                "data_size": args.data_size,
                "iterations": args.iterations,
                "mode": args.mode,
            },
            "results": {},
        }
        for name, row in all_rows.items():
            output_data["results"][name] = {
                "native_ops": row.native_ops,
                "litebox_ops": row.litebox_ops,
                "native_avg_ops": row.native_avg_ops,
                "litebox_avg_ops": row.litebox_avg_ops,
                "native_lat": row.native_lat,
                "litebox_lat": row.litebox_lat,
                "ratio": row.ratio,
                "overhead_pct": row.overhead_pct,
            }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to {args.output}")

    # ── Cleanup ─────────────────────────────────────────────────────────

    if cleanup_work_dir:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
