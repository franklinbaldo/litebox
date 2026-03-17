#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Run Node.js HTTP server benchmarks natively and under LiteBox, then compare.

A minimal Node.js HTTP server runs inside LiteBox (or natively), and wrk
drives requests from the host.  Reports requests/sec and latency.

Prerequisites:
  - node installed on host
  - wrk installed on host (sudo apt install wrk)
  - For LiteBox mode: TUN device set up (see litebox_platform_linux_userland/scripts/tun-setup.sh)

Usage:
    python3 run_node_http.py [options]

Examples:
    # Run both native and LiteBox
    python3 run_node_http.py --release

    # Run only LiteBox
    python3 run_node_http.py --mode litebox --release

    # Override duration, threads, connections
    python3 run_node_http.py --duration 15 --threads 2 --connections 50 --release

    # Save results to JSON
    python3 run_node_http.py --release --output results.json
"""

import argparse
import json
import math
import os
import re
import shutil
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
NODE_PORT = 8199  # non-default port to avoid conflicts
TUN_DEVICE = "tun99"

# Minimal HTTP server script (no dependencies, single-process).
# Reads RESPONSE_SIZE env var to control the response body size in bytes.
HTTP_SERVER_JS = """\
const http = require('http');

const HOST = process.env.BIND_ADDR || '0.0.0.0';
const PORT = parseInt(process.env.PORT || '8199', 10);
const RESPONSE_SIZE = parseInt(process.env.RESPONSE_SIZE || '14', 10);

// Build a body of exactly RESPONSE_SIZE bytes.
const body = RESPONSE_SIZE <= 14
    ? 'Hello, World!\\n'
    : 'X'.repeat(RESPONSE_SIZE - 1) + '\\n';
const headers = {
    'Content-Type': 'text/plain',
    'Content-Length': Buffer.byteLength(body),
};

const server = http.createServer((req, res) => {
    res.writeHead(200, headers);
    res.end(body);
});

server.listen(PORT, HOST, () => {
    process.stderr.write(`Listening on ${HOST}:${PORT} (response ${body.length} bytes)\\n`);
});
"""


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
class BenchmarkResult:
    """Parsed result from a single wrk run."""

    requests_per_sec: float
    avg_latency_ms: float
    transfer_per_sec: str  # e.g. "1.23MB"
    total_requests: int
    elapsed: float  # wall-clock seconds
    raw_output: str = ""

    def to_dict(self) -> dict:
        return {
            "requests_per_sec": self.requests_per_sec,
            "avg_latency_ms": self.avg_latency_ms,
            "transfer_per_sec": self.transfer_per_sec,
            "total_requests": self.total_requests,
            "elapsed": self.elapsed,
        }


def parse_wrk_output(output: str) -> Optional[BenchmarkResult]:
    """
    Parse wrk output.

    Example output:
        Running 10s test @ http://127.0.0.1:8199
          2 threads and 50 connections
          Thread Stats   Avg      Stdev     Max   +/- Stdev
            Latency     1.23ms  456.78us   9.87ms   76.54%
            Req/Sec    20.50k     1.23k   25.00k    68.00%
          409876 requests in 10.00s, 50.12MB read
        Requests/sec:  40987.60
        Transfer/sec:      5.01MB
    """
    rps_match = re.search(r"Requests/sec:\s+([0-9.]+)", output)
    transfer_match = re.search(r"Transfer/sec:\s+(\S+)", output)
    latency_match = re.search(
        r"Latency\s+([0-9.]+)(us|ms|s)", output,
    )
    requests_match = re.search(r"(\d+)\s+requests\s+in\s+", output)

    if rps_match is None:
        return None

    rps = float(rps_match.group(1))

    # Parse latency to ms
    avg_latency_ms = 0.0
    if latency_match:
        val = float(latency_match.group(1))
        unit = latency_match.group(2)
        if unit == "us":
            avg_latency_ms = val / 1000.0
        elif unit == "ms":
            avg_latency_ms = val
        elif unit == "s":
            avg_latency_ms = val * 1000.0

    transfer = transfer_match.group(1) if transfer_match else "N/A"
    total_reqs = int(requests_match.group(1)) if requests_match else 0

    return BenchmarkResult(
        requests_per_sec=rps,
        avg_latency_ms=avg_latency_ms,
        transfer_per_sec=transfer,
        total_requests=total_reqs,
        elapsed=0.0,
        raw_output=output,
    )


# ── Server Management ───────────────────────────────────────────────────────


def wait_for_http(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait until the HTTP server is accepting connections."""
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


# ── Native Runner ───────────────────────────────────────────────────────────


def run_native(
    duration: int,
    threads: int,
    connections: int,
    response_size: int,
    work_dir: Path,
) -> Optional[BenchmarkResult]:
    """Run Node.js HTTP server natively and benchmark with wrk."""
    node_path = locate_command("node")
    wrk_path = locate_command("wrk")
    if node_path is None:
        print("  [SKIP] node not found on PATH")
        return None
    if wrk_path is None:
        print("  [SKIP] wrk not found on PATH")
        return None

    # Write server script
    server_js = work_dir / "server.js"
    server_js.write_text(HTTP_SERVER_JS)

    env = os.environ.copy()
    env["BIND_ADDR"] = "127.0.0.1"
    env["PORT"] = str(NODE_PORT)
    env["RESPONSE_SIZE"] = str(response_size)

    # Start server
    server_proc = subprocess.Popen(
        [str(node_path), str(server_js)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
    )

    try:
        print("  Waiting for native Node.js server...")
        if not wait_for_http("127.0.0.1", NODE_PORT):
            print("  [FAIL] Node.js server did not start in time")
            return None

        # Run wrk
        url = f"http://127.0.0.1:{NODE_PORT}/"
        cmd = [
            str(wrk_path),
            "-t", str(threads),
            "-c", str(connections),
            "-d", f"{duration}s",
            url,
        ]
        print(f"  Running: {' '.join(cmd)}")
        t0 = time.monotonic()
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=duration * 3 + 30)
        except subprocess.TimeoutExpired:
            print("  [TIMEOUT]")
            return None
        elapsed = time.monotonic() - t0

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            print(f"  [FAIL] wrk exit code {result.returncode}")
            print(f"  stderr: {stderr[:500]}")
            return None

        stdout = result.stdout.decode("utf-8", errors="replace")
        parsed = parse_wrk_output(stdout)
        if parsed is None:
            print(f"  [FAIL] no results parsed from wrk output:\n{stdout[:500]}")
            return None

        parsed.elapsed = elapsed
        return parsed

    finally:
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
    node_path: Path,
    server_js_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[tuple[Path, Path]]:
    """Prepare rootfs tar for LiteBox using litebox_packager."""
    tar_path = work_dir / "rootfs_node_http.tar"
    rewritten = work_dir / "node.hooked"

    # Reuse if already prepared
    if tar_path.exists() and rewritten.exists():
        return tar_path, rewritten

    if packager_path:
        cmd = [str(packager_path)]
    else:
        cmd = ["cargo", "run", "-p", "litebox_packager", "--"]

    cmd += [
        str(node_path),
        "--include", f"{server_js_path}:/app/server.js",
        "-o", str(tar_path),
    ]

    print("  Packaging with litebox_packager...")
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Error: packager failed: {stderr[:500]}")
        return None

    try:
        _extract_rewritten_binary(tar_path, node_path, rewritten)
    except RuntimeError as e:
        print(f"  Error: {e}")
        return None

    return tar_path, rewritten


def run_litebox(
    duration: int,
    threads: int,
    connections: int,
    response_size: int,
    runner_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[BenchmarkResult]:
    """Run Node.js HTTP server under LiteBox and benchmark from host."""
    node_path = locate_command("node")
    wrk_path = locate_command("wrk")
    if node_path is None:
        print("  [SKIP] node not found on PATH")
        return None
    if wrk_path is None:
        print("  [SKIP] wrk not found on PATH")
        return None

    # Write server script
    server_js = work_dir / "server.js"
    server_js.write_text(HTTP_SERVER_JS)

    prepared = prepare_litebox_rootfs(
        node_path, server_js, work_dir, packager_path,
    )
    if prepared is None:
        return None

    tar_path, rewritten = prepared

    # Start Node.js inside LiteBox
    server_cmd = [
        str(runner_path),
        "--unstable",
        "--interception-backend", "rewriter",
        "--env", "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
        "--env", "HOME=/",
        "--env", f"BIND_ADDR={GUEST_IP}",
        "--env", f"PORT={NODE_PORT}",
        "--env", f"RESPONSE_SIZE={response_size}",
        "--tun-device-name", TUN_DEVICE,
        "--initial-files", str(tar_path),
        str(rewritten),
        "/app/server.js",
    ]

    print(f"  Starting LiteBox Node.js:\n    {' '.join(server_cmd)}")
    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        print(f"  Waiting for Node.js at {GUEST_IP}:{NODE_PORT}...")
        if not wait_for_http(GUEST_IP, NODE_PORT, timeout=60.0):
            stderr = ""
            try:
                _, stderr_bytes = server_proc.communicate(timeout=2)
                stderr = stderr_bytes.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                pass
            print("  [FAIL] LiteBox Node.js did not start in time")
            if stderr:
                print(f"  stderr (last 500): ...{stderr[-500:]}")
            return None

        # Run wrk from host
        url = f"http://{GUEST_IP}:{NODE_PORT}/"
        cmd = [
            str(wrk_path),
            "-t", str(threads),
            "-c", str(connections),
            "-d", f"{duration}s",
            url,
        ]
        print(f"  Running: {' '.join(cmd)}")
        t0 = time.monotonic()
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=duration * 3 + 30)
        except subprocess.TimeoutExpired:
            print("  [TIMEOUT]")
            return None
        elapsed = time.monotonic() - t0

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            print(f"  [FAIL] wrk exit code {result.returncode}")
            print(f"  stderr: {stderr[:500]}")
            return None

        stdout = result.stdout.decode("utf-8", errors="replace")
        parsed = parse_wrk_output(stdout)
        if parsed is None:
            print(f"  [FAIL] no results parsed from wrk output:\n{stdout[:500]}")
            return None

        parsed.elapsed = elapsed
        return parsed

    finally:
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
    native_rps: list[float] = field(default_factory=list)
    litebox_rps: list[float] = field(default_factory=list)
    native_lat: list[float] = field(default_factory=list)
    litebox_lat: list[float] = field(default_factory=list)

    @property
    def native_avg_rps(self) -> Optional[float]:
        return sum(self.native_rps) / len(self.native_rps) if self.native_rps else None

    @property
    def litebox_avg_rps(self) -> Optional[float]:
        return sum(self.litebox_rps) / len(self.litebox_rps) if self.litebox_rps else None

    @property
    def native_avg_lat(self) -> Optional[float]:
        return sum(self.native_lat) / len(self.native_lat) if self.native_lat else None

    @property
    def litebox_avg_lat(self) -> Optional[float]:
        return sum(self.litebox_lat) / len(self.litebox_lat) if self.litebox_lat else None

    @property
    def rps_ratio(self) -> Optional[float]:
        n = self.native_avg_rps
        lb = self.litebox_avg_rps
        if n and lb and n > 0:
            return lb / n
        return None

    @property
    def overhead_pct(self) -> Optional[float]:
        n = self.native_avg_rps
        lb = self.litebox_avg_rps
        if n and lb and n > 0:
            return ((n - lb) / n) * 100.0
        return None


def print_comparison_table(row: ComparisonRow):
    """Print formatted comparison table."""
    print()
    print("=" * 90)
    print(
        f"{'Metric':<25} {'Native':>16} {'LiteBox':>16}"
        f" {'Ratio':>8} {'Overhead':>10}"
    )
    print("-" * 90)

    # Requests/sec
    native_rps = f"{row.native_avg_rps:,.0f}" if row.native_avg_rps is not None else "N/A"
    litebox_rps = f"{row.litebox_avg_rps:,.0f}" if row.litebox_avg_rps is not None else "N/A"
    ratio_str = f"{row.rps_ratio:.4f}" if row.rps_ratio is not None else "N/A"
    overhead_str = f"{row.overhead_pct:+.2f}%" if row.overhead_pct is not None else "N/A"
    print(
        f"{'Requests/sec':<25} {native_rps:>16} {litebox_rps:>16}"
        f" {ratio_str:>8} {overhead_str:>10}"
    )

    # Avg latency
    native_lat = f"{row.native_avg_lat:.2f}ms" if row.native_avg_lat is not None else "N/A"
    litebox_lat = f"{row.litebox_avg_lat:.2f}ms" if row.litebox_avg_lat is not None else "N/A"
    if row.native_avg_lat and row.litebox_avg_lat and row.native_avg_lat > 0:
        lat_ratio = f"{row.litebox_avg_lat / row.native_avg_lat:.4f}"
    else:
        lat_ratio = "N/A"
    print(
        f"{'Avg Latency':<25} {native_lat:>16} {litebox_lat:>16}"
        f" {lat_ratio:>8} {'':>10}"
    )

    print("=" * 90)
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
    global TUN_DEVICE, NODE_PORT
    parser = argparse.ArgumentParser(
        description="Run Node.js HTTP server benchmarks natively and under LiteBox.",
    )
    parser.add_argument(
        "--mode",
        choices=["both", "native", "litebox"],
        default="both",
        help="Run mode (default: both)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Duration of each wrk run in seconds (default: 10)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=2,
        help="Number of wrk threads (default: 2)",
    )
    parser.add_argument(
        "--connections",
        type=int,
        default=8,
        help="Number of concurrent connections (default: 8; LiteBox caps backlog at 8)",
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
        "--response-size",
        type=int,
        default=14,
        help="Response body size in bytes (default: 14). Larger values stress "
             "the network data path; smaller values stress syscall overhead.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=NODE_PORT,
        help=f"Node.js server port (default: {NODE_PORT})",
    )

    args = parser.parse_args()

    TUN_DEVICE = args.tun_device
    NODE_PORT = args.port

    # Check prerequisites
    if locate_command("node") is None:
        print("Error: node not found on PATH.")
        print("Install Node.js: https://nodejs.org/ or via nvm")
        sys.exit(1)
    if locate_command("wrk") is None:
        print("Error: wrk not found on PATH.")
        print("Install wrk: sudo apt install wrk")
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
        work_dir = Path(tempfile.mkdtemp(prefix="litebox_node_bench_"))
        cleanup_work_dir = True

    print(f"Workspace root: {workspace_root}")
    print(f"Work dir:       {work_dir}")
    print(f"Duration:       {args.duration}s per run")
    print(f"Threads:        {args.threads}")
    print(f"Connections:    {args.connections}")
    print(f"Response size:  {args.response_size} bytes")
    print(f"Iterations:     {args.iterations}")
    print(f"Mode:           {args.mode}")
    print(f"Port:           {NODE_PORT}")
    if run_litebox_mode:
        print(f"TUN device:     {TUN_DEVICE}")
        print(f"Runner:         {runner_path}")
        print(f"Packager:       {packager_path or 'cargo run'}")
    print()

    row = ComparisonRow(name="node-http")

    # ── Native runs ─────────────────────────────────────────────────────

    if args.mode in ("both", "native"):
        print(f"[Native] Node.js HTTP (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_native(
                args.duration, args.threads, args.connections,
                args.response_size, work_dir,
            )
            if result:
                row.native_rps.append(result.requests_per_sec)
                row.native_lat.append(result.avg_latency_ms)
                print(
                    f"    {result.requests_per_sec:,.0f} req/s, "
                    f"avg latency {result.avg_latency_ms:.2f}ms"
                )

    # ── LiteBox runs ────────────────────────────────────────────────────

    if run_litebox_mode:
        print(f"[LiteBox] Node.js HTTP (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_litebox(
                args.duration, args.threads, args.connections,
                args.response_size, runner_path, work_dir, packager_path,
            )
            if result:
                row.litebox_rps.append(result.requests_per_sec)
                row.litebox_lat.append(result.avg_latency_ms)
                print(
                    f"    {result.requests_per_sec:,.0f} req/s, "
                    f"avg latency {result.avg_latency_ms:.2f}ms"
                )

    # ── Results ─────────────────────────────────────────────────────────

    print_comparison_table(row)

    # ── Save to JSON ────────────────────────────────────────────────────

    if args.output:
        output_data = {
            "config": {
                "duration": args.duration,
                "threads": args.threads,
                "connections": args.connections,
                "response_size": args.response_size,
                "iterations": args.iterations,
                "mode": args.mode,
            },
            "results": {
                "native_rps": row.native_rps,
                "litebox_rps": row.litebox_rps,
                "native_lat": row.native_lat,
                "litebox_lat": row.litebox_lat,
                "native_avg_rps": row.native_avg_rps,
                "litebox_avg_rps": row.litebox_avg_rps,
                "native_avg_lat": row.native_avg_lat,
                "litebox_avg_lat": row.litebox_avg_lat,
                "rps_ratio": row.rps_ratio,
                "overhead_pct": row.overhead_pct,
            },
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to {args.output}")

    # ── Cleanup ─────────────────────────────────────────────────────────

    if cleanup_work_dir:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
