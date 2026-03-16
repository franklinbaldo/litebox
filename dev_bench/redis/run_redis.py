#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Run Redis benchmarks natively and under LiteBox, then compare results.

Redis is single-process, in-memory, and exercises syscalls + networking heavily.
redis-benchmark from outside drives SET/GET throughput (ops/sec).

Prerequisites:
  - redis-server and redis-benchmark installed on host
  - For LiteBox mode: TUN device set up (see litebox_platform_linux_userland/scripts/tun-setup.sh)

Usage:
    python3 run_redis.py [options]

Examples:
    # Run both native and LiteBox (default: 100k requests, 50 clients)
    python3 run_redis.py --release

    # Run only native
    python3 run_redis.py --mode native

    # Run only LiteBox
    python3 run_redis.py --mode litebox --release

    # Override request count and client count
    python3 run_redis.py --requests 200000 --clients 20 --release

    # More iterations for stable results
    python3 run_redis.py --iterations 5 --release

    # Save results to JSON
    python3 run_redis.py --release --output results.json
"""

import argparse
import json
import math
import os
import re
import shutil
import signal
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
REDIS_PORT = 6399  # non-default port to avoid conflict with host redis
TUN_DEVICE = "tun99"

# Tests to run with redis-benchmark (each produces ops/sec)
BENCHMARK_TESTS = ["SET", "GET", "INCR", "LPUSH", "RPUSH", "LPOP", "RPOP",
                   "SADD", "HSET", "MSET"]


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


def find_preload_libs(binary: Path) -> list[str]:
    """
    Find shared libraries that need LD_PRELOAD due to static TLS.

    Libraries like jemalloc use initial-exec TLS and fail with
    "cannot allocate memory in static TLS block" when loaded late.
    Preloading them ensures early TLS allocation.
    """
    preload_names = {"libjemalloc"}
    result = subprocess.run(
        ["ldd", str(binary)],
        capture_output=True,
    )
    if result.returncode != 0:
        return []

    libs = []
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        for name in preload_names:
            if name in line:
                # Parse "libjemalloc.so.2 => /lib/x86_64-linux-gnu/libjemalloc.so.2 (0x...)"
                m = re.search(r"=>\s+(\S+)", line)
                if m:
                    libs.append(m.group(1))
    return libs


# ── Result Parsing ──────────────────────────────────────────────────────────


@dataclass
class TestResult:
    """Result for a single redis-benchmark test (e.g. SET, GET)."""

    name: str
    ops_per_sec: float


@dataclass
class BenchmarkResult:
    """Parsed results from a single redis-benchmark run."""

    tests: list[TestResult]
    elapsed: float  # wall-clock seconds
    raw_output: str = ""

    def to_dict(self) -> dict:
        return {
            "elapsed": self.elapsed,
            "tests": {t.name: t.ops_per_sec for t in self.tests},
        }


def parse_redis_benchmark_output(output: str) -> list[TestResult]:
    """
    Parse redis-benchmark --csv output.

    CSV output looks like:
        "PING_INLINE","78740.16"
        "PING_MBULK","80000.00"
        "SET","79365.08"
        "GET","80645.16"
        ...
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'"([^"]+)","([0-9.]+)"', line)
        if m:
            name = m.group(1)
            ops = float(m.group(2))
            results.append(TestResult(name=name, ops_per_sec=ops))
    return results


# ── Server Management ───────────────────────────────────────────────────────


def wait_for_redis(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait until redis-server is accepting connections."""
    redis_cli = locate_command("redis-cli")
    if redis_cli is None:
        # Fallback: just try connecting
        import socket

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                s = socket.create_connection((host, port), timeout=1.0)
                s.close()
                return True
            except OSError:
                time.sleep(0.1)
        return False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            [str(redis_cli), "-h", host, "-p", str(port), "PING"],
            capture_output=True,
            timeout=5,
        )
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        if stdout == "PONG":
            return True
        time.sleep(0.1)
    return False


def write_redis_config(config_path: Path, bind_addr: str, port: int) -> None:
    """Write a minimal redis.conf for benchmarking (no persistence, no fork)."""
    config_path.write_text(
        f"bind {bind_addr}\n"
        f"port {port}\n"
        "protected-mode no\n"
        "daemonize no\n"
        # Disable all persistence to avoid fork
        'save ""\n'
        "appendonly no\n"
        "loglevel warning\n"
    )


# ── Native Runner ───────────────────────────────────────────────────────────


def run_native(
    requests: int,
    clients: int,
    tests: list[str],
    work_dir: Path,
) -> Optional[BenchmarkResult]:
    """Run redis-server natively and benchmark it."""
    redis_server = locate_command("redis-server")
    redis_benchmark = locate_command("redis-benchmark")
    if redis_server is None:
        print("  [SKIP] redis-server not found on PATH")
        return None
    if redis_benchmark is None:
        print("  [SKIP] redis-benchmark not found on PATH")
        return None

    config_path = work_dir / "redis_native.conf"
    write_redis_config(config_path, "127.0.0.1", REDIS_PORT)

    # Start server
    server_proc = subprocess.Popen(
        [str(redis_server), str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        print("  Waiting for native redis-server...")
        if not wait_for_redis("127.0.0.1", REDIS_PORT):
            print("  [FAIL] redis-server did not start in time")
            return None

        # Run benchmark
        tests_arg = ",".join(tests)
        cmd = [
            str(redis_benchmark),
            "-h", "127.0.0.1",
            "-p", str(REDIS_PORT),
            "-n", str(requests),
            "-c", str(clients),
            "-t", tests_arg,
            "--csv",
        ]
        print(f"  Running: {' '.join(cmd)}")
        t0 = time.monotonic()
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("  [TIMEOUT]")
            return None
        elapsed = time.monotonic() - t0

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            print(f"  [FAIL] redis-benchmark exit code {result.returncode}")
            print(f"  stderr: {stderr[:500]}")
            return None

        stdout = result.stdout.decode("utf-8", errors="replace")
        test_results = parse_redis_benchmark_output(stdout)
        if not test_results:
            print(f"  [FAIL] no results parsed from output:\n{stdout[:500]}")
            return None

        return BenchmarkResult(
            tests=test_results,
            elapsed=elapsed,
            raw_output=stdout,
        )
    finally:
        # Shutdown server gracefully
        redis_cli = locate_command("redis-cli")
        if redis_cli:
            try:
                subprocess.run(
                    [str(redis_cli), "-h", "127.0.0.1", "-p", str(REDIS_PORT), "SHUTDOWN", "NOSAVE"],
                    capture_output=True,
                    timeout=5,
                )
            except subprocess.TimeoutExpired:
                pass  # server_proc.terminate() below will clean up
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
    redis_server_path: Path,
    redis_config_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[tuple[Path, Path]]:
    """Prepare rootfs tar for LiteBox using litebox_packager."""
    tar_path = work_dir / "rootfs_redis.tar"
    rewritten = work_dir / "redis-server.hooked"

    # Reuse if already prepared
    if tar_path.exists() and rewritten.exists():
        return tar_path, rewritten

    if packager_path:
        cmd = [str(packager_path)]
    else:
        cmd = ["cargo", "run", "-p", "litebox_packager", "--"]

    cmd += [
        str(redis_server_path),
        "--include", f"{redis_config_path}:/etc/redis.conf",
        "-o", str(tar_path),
    ]

    print("  Packaging with litebox_packager...")
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Error: packager failed: {stderr[:500]}")
        return None

    try:
        _extract_rewritten_binary(tar_path, redis_server_path, rewritten)
    except RuntimeError as e:
        print(f"  Error: {e}")
        return None

    return tar_path, rewritten


def run_litebox(
    requests: int,
    clients: int,
    tests: list[str],
    runner_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[BenchmarkResult]:
    """Run redis-server under LiteBox and benchmark from host."""
    redis_server = locate_command("redis-server")
    redis_benchmark = locate_command("redis-benchmark")
    if redis_server is None:
        print("  [SKIP] redis-server not found on PATH")
        return None
    if redis_benchmark is None:
        print("  [SKIP] redis-benchmark not found on PATH")
        return None

    # Write config for guest (bind to guest IP)
    config_path = work_dir / "redis_litebox.conf"
    write_redis_config(config_path, GUEST_IP, REDIS_PORT)

    prepared = prepare_litebox_rootfs(
        redis_server, config_path, work_dir, packager_path,
    )
    if prepared is None:
        return None

    tar_path, rewritten = prepared

    # Detect libraries needing LD_PRELOAD (e.g. jemalloc with static TLS)
    preload_libs = find_preload_libs(redis_server)

    # Start redis-server inside LiteBox in a subprocess
    server_cmd = [
        str(runner_path),
        "--unstable",
        "--interception-backend", "rewriter",
        "--env", "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
        "--env", "HOME=/",
    ]
    if preload_libs:
        preload_val = ":".join(preload_libs)
        server_cmd += ["--env", f"LD_PRELOAD={preload_val}"]
    server_cmd += [
        "--tun-device-name", TUN_DEVICE,
        "--initial-files", str(tar_path),
        str(rewritten),
        "/etc/redis.conf",
    ]

    print(f"  Starting LiteBox redis-server:\n    {' '.join(server_cmd)}")
    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        print(f"  Waiting for redis-server at {GUEST_IP}:{REDIS_PORT}...")
        if not wait_for_redis(GUEST_IP, REDIS_PORT, timeout=60.0):
            stderr = ""
            try:
                _, stderr_bytes = server_proc.communicate(timeout=2)
                stderr = stderr_bytes.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                pass
            print("  [FAIL] LiteBox redis-server did not start in time")
            if stderr:
                print(f"  stderr (last 500): ...{stderr[-500:]}")
            return None

        # Run benchmark from host side
        tests_arg = ",".join(tests)
        cmd = [
            str(redis_benchmark),
            "-h", GUEST_IP,
            "-p", str(REDIS_PORT),
            "-n", str(requests),
            "-c", str(clients),
            "-t", tests_arg,
            "--csv",
        ]
        print(f"  Running: {' '.join(cmd)}")
        t0 = time.monotonic()
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("  [TIMEOUT]")
            return None
        elapsed = time.monotonic() - t0

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            print(f"  [FAIL] redis-benchmark exit code {result.returncode}")
            print(f"  stderr: {stderr[:500]}")
            return None

        stdout = result.stdout.decode("utf-8", errors="replace")
        test_results = parse_redis_benchmark_output(stdout)
        if not test_results:
            print(f"  [FAIL] no results parsed from output:\n{stdout[:500]}")
            return None

        return BenchmarkResult(
            tests=test_results,
            elapsed=elapsed,
            raw_output=stdout,
        )
    finally:
        # Shutdown server
        redis_cli = locate_command("redis-cli")
        if redis_cli:
            try:
                subprocess.run(
                    [str(redis_cli), "-h", GUEST_IP, "-p", str(REDIS_PORT),
                     "SHUTDOWN", "NOSAVE"],
                    capture_output=True,
                    timeout=5,
                )
            except subprocess.TimeoutExpired:
                pass  # server_proc.terminate() below will clean up
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

    @property
    def native_avg(self) -> Optional[float]:
        return (
            sum(self.native_ops) / len(self.native_ops)
            if self.native_ops
            else None
        )

    @property
    def litebox_avg(self) -> Optional[float]:
        return (
            sum(self.litebox_ops) / len(self.litebox_ops)
            if self.litebox_ops
            else None
        )

    @property
    def overhead_pct(self) -> Optional[float]:
        """Overhead %. Positive means LiteBox is slower (lower ops/sec)."""
        n = self.native_avg
        lb = self.litebox_avg
        if n and lb and n > 0:
            return ((n - lb) / n) * 100.0
        return None

    @property
    def ratio(self) -> Optional[float]:
        """Throughput ratio (LiteBox / Native). Values near 1.0 = no overhead."""
        n = self.native_avg
        lb = self.litebox_avg
        if n and lb and n > 0:
            return lb / n
        return None


def print_comparison_table(rows: list[ComparisonRow]):
    """Print formatted comparison table (higher ops/sec is better)."""
    print()
    print("=" * 85)
    print(
        f"{'Test':<15} {'Native (ops/s)':>16} {'LiteBox (ops/s)':>16}"
        f" {'Ratio':>8} {'Overhead':>10}"
    )
    print("-" * 85)

    for row in rows:
        native_str = f"{row.native_avg:,.0f}" if row.native_avg is not None else "N/A"
        litebox_str = (
            f"{row.litebox_avg:,.0f}" if row.litebox_avg is not None else "N/A"
        )
        ratio_str = f"{row.ratio:.4f}" if row.ratio is not None else "N/A"
        overhead_str = (
            f"{row.overhead_pct:+.2f}%" if row.overhead_pct is not None else "N/A"
        )
        print(
            f"{row.name:<15} {native_str:>16} {litebox_str:>16}"
            f" {ratio_str:>8} {overhead_str:>10}"
        )

    print("=" * 85)

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
    global TUN_DEVICE, REDIS_PORT
    parser = argparse.ArgumentParser(
        description="Run Redis benchmarks natively and under LiteBox.",
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
        default=100000,
        help="Number of requests per test (default: 100000)",
    )
    parser.add_argument(
        "--clients",
        type=int,
        default=8,
        help="Number of parallel clients (default: 8)",
    )
    parser.add_argument(
        "--tests",
        nargs="+",
        default=BENCHMARK_TESTS,
        help="Redis tests to run (default: SET GET INCR LPUSH RPUSH LPOP RPOP SADD HSET MSET)",
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
        default=REDIS_PORT,
        help=f"Redis port (default: {REDIS_PORT})",
    )

    args = parser.parse_args()

    TUN_DEVICE = args.tun_device
    REDIS_PORT = args.port

    # Check prerequisites
    if locate_command("redis-server") is None:
        print("Error: redis-server not found on PATH.")
        print("Install Redis: sudo apt install redis-server")
        sys.exit(1)
    if locate_command("redis-benchmark") is None:
        print("Error: redis-benchmark not found on PATH.")
        print("Install Redis tools: sudo apt install redis-tools")
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
        work_dir = Path(tempfile.mkdtemp(prefix="litebox_redis_bench_"))
        cleanup_work_dir = True

    tests_str = ", ".join(args.tests)
    print(f"Workspace root: {workspace_root}")
    print(f"Work dir:       {work_dir}")
    print(f"Requests:       {args.requests}")
    print(f"Clients:        {args.clients}")
    print(f"Tests:          {tests_str}")
    print(f"Iterations:     {args.iterations}")
    print(f"Mode:           {args.mode}")
    print(f"Port:           {REDIS_PORT}")
    if run_litebox_mode:
        print(f"TUN device:     {TUN_DEVICE}")
        print(f"Runner:         {runner_path}")
        print(f"Packager:       {packager_path or 'cargo run'}")
    print()

    # Per-test comparison rows
    all_rows: dict[str, ComparisonRow] = {
        t: ComparisonRow(name=t) for t in args.tests
    }

    # ── Native runs ─────────────────────────────────────────────────────

    if args.mode in ("both", "native"):
        print(f"[Native] Redis benchmark (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_native(
                args.requests, args.clients, args.tests, work_dir,
            )
            if result:
                for t in result.tests:
                    if t.name in all_rows:
                        all_rows[t.name].native_ops.append(t.ops_per_sec)
                        print(f"    {t.name}: {t.ops_per_sec:,.0f} ops/sec")

    # ── LiteBox runs ────────────────────────────────────────────────────

    if run_litebox_mode:
        print(f"[LiteBox] Redis benchmark (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_litebox(
                args.requests, args.clients, args.tests,
                runner_path, work_dir, packager_path,
            )
            if result:
                for t in result.tests:
                    if t.name in all_rows:
                        all_rows[t.name].litebox_ops.append(t.ops_per_sec)
                        print(f"    {t.name}: {t.ops_per_sec:,.0f} ops/sec")

    # ── Results ─────────────────────────────────────────────────────────

    rows = [all_rows[t] for t in args.tests if t in all_rows]
    print_comparison_table(rows)

    # ── Save to JSON ────────────────────────────────────────────────────

    if args.output:
        output_data = {
            "config": {
                "requests": args.requests,
                "clients": args.clients,
                "tests": args.tests,
                "iterations": args.iterations,
                "mode": args.mode,
            },
            "results": {},
        }
        for name, row in all_rows.items():
            output_data["results"][name] = {
                "native_ops": row.native_ops,
                "litebox_ops": row.litebox_ops,
                "native_avg": row.native_avg,
                "litebox_avg": row.litebox_avg,
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
