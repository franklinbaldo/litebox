#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Run LMbench benchmarks natively and under LiteBox, then compare results.

Usage:
    python3 run_lmbench.py [options]

Examples:
    # Run all benchmarks (native only by default, since all require fork)
    python3 run_lmbench.py

    # Run specific benchmarks
    python3 run_lmbench.py --benchmarks lat_syscall_null lat_pipe bw_pipe

    # Run only native
    python3 run_lmbench.py --mode native

    # Run only with LiteBox (requires fork support)
    python3 run_lmbench.py --mode litebox --release

    # Override repetitions for all benchmarks
    python3 run_lmbench.py --repetitions 3

    # Use release build of litebox
    python3 run_lmbench.py --release

    # Save results to JSON
    python3 run_lmbench.py --output results.json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from lmbench_common import (
    ensure_lmbench_built,
    ensure_lmbench_downloaded,
    extract_rewritten_binary,
    find_lmbench_dir,
    find_workspace_root,
)


# ── Benchmark Definitions ──────────────────────────────────────────────────

@dataclass
class BenchmarkDef:
    """Definition of a single LMbench benchmark."""
    name: str
    binary: str                  # executable name in bin/<os>/
    args: list[str]              # arguments after the binary name
    parse_type: str              # "micro", "nano", or "bandwidth"
    default_unit: str            # expected unit ("usec", "nsec", "MB/sec")
    default_repetitions: int = 5 # -N <reps> passed to lmbench
    requires_fork: bool = True   # all lmbench3 benchmarks use fork via benchmp
    description: str = ""
    higher_is_better: bool = False  # True for bandwidth, False for latency


def _lat_syscall_def(subcommand: str, desc: str) -> BenchmarkDef:
    return BenchmarkDef(
        name=f"lat_syscall_{subcommand}",
        binary="lat_syscall",
        args=[subcommand],
        parse_type="micro",
        default_unit="usec",
        description=desc,
    )


def _lat_sig_def(subcommand: str, desc: str) -> BenchmarkDef:
    return BenchmarkDef(
        name=f"lat_sig_{subcommand}",
        binary="lat_sig",
        args=[subcommand],
        parse_type="micro",
        default_unit="usec",
        description=desc,
    )


def _lat_proc_def(subcommand: str, desc: str) -> BenchmarkDef:
    return BenchmarkDef(
        name=f"lat_proc_{subcommand}",
        binary="lat_proc",
        args=[subcommand],
        parse_type="micro",
        default_unit="usec",
        description=desc,
    )


def _bw_mem_def(operation: str, size: str, desc: str) -> BenchmarkDef:
    return BenchmarkDef(
        name=f"bw_mem_{operation}",
        binary="bw_mem",
        args=[size, operation],
        parse_type="bandwidth",
        default_unit="MB/sec",
        description=desc,
        higher_is_better=True,
    )


BENCHMARKS: dict[str, BenchmarkDef] = {
    # ── System call latency ─────────────────────────────────────────────
    "lat_syscall_null": _lat_syscall_def("null", "getppid() latency"),
    "lat_syscall_read": _lat_syscall_def("read", "read /dev/zero latency"),
    "lat_syscall_write": _lat_syscall_def("write", "write /dev/null latency"),
    "lat_syscall_stat": _lat_syscall_def("stat", "stat() latency"),
    "lat_syscall_fstat": _lat_syscall_def("fstat", "fstat() latency"),
    "lat_syscall_open": _lat_syscall_def("open", "open/close latency"),

    # ── Signal latency ──────────────────────────────────────────────────
    "lat_sig_install": _lat_sig_def("install", "signal handler install latency"),
    "lat_sig_catch": _lat_sig_def("catch", "signal catch latency"),
    "lat_sig_prot": _lat_sig_def("prot", "protection fault latency"),

    # ── Pipe latency ────────────────────────────────────────────────────
    "lat_pipe": BenchmarkDef(
        name="lat_pipe",
        binary="lat_pipe",
        args=[],
        parse_type="micro",
        default_unit="usec",
        description="pipe latency",
    ),

    # ── Process creation latency ────────────────────────────────────────
    "lat_proc_fork": _lat_proc_def("fork", "fork+exit latency"),
    "lat_proc_exec": _lat_proc_def("exec", "fork+exec latency"),
    "lat_proc_shell": _lat_proc_def("shell", "fork+/bin/sh latency"),

    # ── Context switch latency ──────────────────────────────────────────
    "lat_ctx": BenchmarkDef(
        name="lat_ctx",
        binary="lat_ctx",
        args=["-s", "0", "2"],
        parse_type="micro",
        default_unit="usec",
        description="context switch latency (2 procs, 0K)",
    ),

    # ── Memory bandwidth ────────────────────────────────────────────────
    "bw_mem_rd": _bw_mem_def("rd", "512k", "memory read bandwidth (512K)"),
    "bw_mem_wr": _bw_mem_def("wr", "512k", "memory write bandwidth (512K)"),
    "bw_mem_cp": _bw_mem_def("cp", "512k", "memory copy bandwidth (512K)"),
    "bw_mem_bzero": _bw_mem_def("bzero", "512k", "memory bzero bandwidth (512K)"),

    # ── Pipe bandwidth ──────────────────────────────────────────────────
    "bw_pipe": BenchmarkDef(
        name="bw_pipe",
        binary="bw_pipe",
        args=[],
        parse_type="bandwidth",
        default_unit="MB/sec",
        description="pipe bandwidth",
        higher_is_better=True,
    ),

    # ── Unix socket bandwidth ───────────────────────────────────────────
    "bw_unix": BenchmarkDef(
        name="bw_unix",
        binary="bw_unix",
        args=[],
        parse_type="bandwidth",
        default_unit="MB/sec",
        description="unix socket bandwidth",
        higher_is_better=True,
    ),
}

DEFAULT_BENCHMARKS = [
    # Latency
    "lat_syscall_null", "lat_syscall_read", "lat_syscall_write",
    "lat_syscall_stat", "lat_syscall_fstat", "lat_syscall_open",
    "lat_sig_install", "lat_sig_catch", "lat_sig_prot",
    "lat_pipe",
    "lat_proc_fork", "lat_proc_exec", "lat_proc_shell",
    "lat_ctx",
    # Bandwidth
    "bw_mem_rd", "bw_mem_wr", "bw_mem_cp", "bw_mem_bzero",
    "bw_pipe", "bw_unix",
]


# ── Result Parsing ─────────────────────────────────────────────────────────

@dataclass
class BenchmarkResult:
    """Parsed result from a single benchmark run."""
    name: str
    value: float
    unit: str
    elapsed: Optional[float] = None  # wall-clock seconds
    raw_stderr: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "elapsed": self.elapsed,
        }


def parse_lmbench_output(stderr: str, parse_type: str) -> Optional[tuple[float, str]]:
    """
    Parse LMbench output from stderr and return ``(value, unit)``.

    Output formats handled:

    * ``micro()``:  ``Label: X.XXXX microseconds``
    * ``nano()``:   ``Label: X.XX nanoseconds``
    * ``bandwidth()`` non-verbose:  ``X.XX X.XX``  (MB  MB/sec)
    * ``bandwidth()`` verbose:  ``X.XXXX MB in X.XXXX secs, X.XXXX MB/sec``
    """
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue

        if parse_type == "micro":
            m = re.search(r":\s+([\d.]+)\s+microseconds", line)
            if m:
                return float(m.group(1)), "usec"

        elif parse_type == "nano":
            m = re.search(r":\s+([\d.]+)\s+nanoseconds", line)
            if m:
                return float(m.group(1)), "nsec"

        elif parse_type == "bandwidth":
            # Verbose: "X.XXXX MB/sec"
            m = re.search(r"([\d.]+)\s+MB/sec", line)
            if m:
                return float(m.group(1)), "MB/sec"
            # Non-verbose: two numbers "X.XX X.XX" where second is MB/sec
            m = re.match(r"^([\d.]+)\s+([\d.]+)\s*$", line)
            if m:
                return float(m.group(2)), "MB/sec"

    return None


# ── Native Runner ──────────────────────────────────────────────────────────

def run_native(
    bin_dir: Path,
    bench: BenchmarkDef,
    repetitions: int,
) -> Optional[BenchmarkResult]:
    """Run a benchmark natively (without LiteBox)."""
    binary = bin_dir / bench.binary
    if not binary.exists():
        print(f"  [SKIP] {bench.name}: binary not found at {binary}")
        return None

    cmd = [str(binary), "-N", str(repetitions)] + bench.args
    print(f"  Running: {' '.join(cmd)}")
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {bench.name}")
        return None
    elapsed = time.monotonic() - t0

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  [FAIL] {bench.name} exited with {result.returncode}")
        print(f"  stderr (last 300 chars): ...{stderr[-300:]}")
        return None

    stderr = result.stderr.decode("utf-8", errors="replace")
    parsed = parse_lmbench_output(stderr, bench.parse_type)
    if parsed is None:
        print(f"  [FAIL] {bench.name}: could not parse output:\n{stderr[:500]}")
        return None

    value, unit = parsed
    return BenchmarkResult(
        name=bench.name, value=value, unit=unit,
        elapsed=elapsed, raw_stderr=stderr,
    )


# ── LiteBox Runner ─────────────────────────────────────────────────────────

def prepare_litebox_rootfs(
    bin_dir: Path,
    bench: BenchmarkDef,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[tuple[Path, Path]]:
    """
    Prepare the rootfs tar for a LiteBox benchmark run using litebox_packager.

    Returns (tar_path, rewritten_binary_path) or None on failure.
    """
    binary = bin_dir / bench.binary
    if not binary.exists():
        print(f"  [SKIP] {bench.name}: binary not found at {binary}")
        return None

    tar_path = work_dir / f"rootfs_{bench.name}.tar"

    if packager_path:
        cmd = [str(packager_path)]
    else:
        cmd = ["cargo", "run", "-p", "litebox_packager", "--"]

    cmd += [str(binary), "-o", str(tar_path)]

    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Error: packager failed for {bench.name}: {stderr[:500]}")
        return None

    rewritten = work_dir / f"{bench.binary}.hooked"
    try:
        extract_rewritten_binary(tar_path, binary, rewritten)
    except RuntimeError as e:
        print(f"  Error: {e}")
        return None

    return tar_path, rewritten


def run_litebox(
    bin_dir: Path,
    bench: BenchmarkDef,
    repetitions: int,
    runner_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[BenchmarkResult]:
    """Run a benchmark under LiteBox on Linux."""
    prepared = prepare_litebox_rootfs(
        bin_dir, bench, work_dir, packager_path,
    )
    if prepared is None:
        return None

    tar_path, rewritten = prepared

    cmd = [
        str(runner_path),
        "--unstable",
        "--interception-backend", "rewriter",
        "--env", "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
        "--env", "HOME=/",
        "--initial-files", str(tar_path),
        str(rewritten),
        "-N", str(repetitions),
    ] + bench.args

    print(f"  Running: {' '.join(cmd)}")
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {bench.name}")
        return None
    elapsed = time.monotonic() - t0

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  [FAIL] {bench.name} exited with {result.returncode}")
        print(f"  stderr (last 300 chars): ...{stderr[-300:]}")
        return None

    stderr = result.stderr.decode("utf-8", errors="replace")
    parsed = parse_lmbench_output(stderr, bench.parse_type)
    if parsed is None:
        print(f"  [FAIL] {bench.name}: could not parse output:\n{stderr[:500]}")
        return None

    value, unit = parsed
    return BenchmarkResult(
        name=bench.name, value=value, unit=unit,
        elapsed=elapsed, raw_stderr=stderr,
    )


# ── Comparison & Reporting ─────────────────────────────────────────────────

@dataclass
class ComparisonRow:
    name: str
    unit: str
    higher_is_better: bool = False
    native_values: list[float] = field(default_factory=list)
    litebox_values: list[float] = field(default_factory=list)

    @property
    def native_avg(self) -> Optional[float]:
        return sum(self.native_values) / len(self.native_values) if self.native_values else None

    @property
    def litebox_avg(self) -> Optional[float]:
        return sum(self.litebox_values) / len(self.litebox_values) if self.litebox_values else None

    @property
    def overhead_pct(self) -> Optional[float]:
        n = self.native_avg
        l = self.litebox_avg
        if n is None or l is None or n == 0:
            return None
        if self.higher_is_better:
            # Bandwidth: overhead = (native - litebox) / native * 100
            return ((n - l) / n) * 100.0
        else:
            # Latency: overhead = (litebox - native) / native * 100
            return ((l - n) / n) * 100.0

    @property
    def ratio(self) -> Optional[float]:
        n = self.native_avg
        l = self.litebox_avg
        if n is None or l is None or n == 0:
            return None
        return l / n


def print_comparison_table(rows: list[ComparisonRow]):
    """Print a formatted comparison table."""
    print()
    print("=" * 90)
    print(f"{'Benchmark':<25} {'Unit':<8} {'Native':>12} {'LiteBox':>12} {'Ratio':>8} {'Overhead':>10}")
    print("-" * 90)

    for row in rows:
        native_str = f"{row.native_avg:.4f}" if row.native_avg is not None else "N/A"
        litebox_str = f"{row.litebox_avg:.4f}" if row.litebox_avg is not None else "N/A"
        ratio_str = f"{row.ratio:.4f}" if row.ratio is not None else "N/A"
        overhead_str = f"{row.overhead_pct:.2f}%" if row.overhead_pct is not None else "N/A"
        print(f"{row.name:<25} {row.unit:<8} {native_str:>12} {litebox_str:>12} {ratio_str:>8} {overhead_str:>10}")

    print("=" * 90)


def print_native_table(rows: list[ComparisonRow]):
    """Print a table for native-only results."""
    print()
    print("=" * 60)
    print(f"{'Benchmark':<25} {'Unit':<8} {'Value':>12} {'Description'}")
    print("-" * 60)

    for row in rows:
        val_str = f"{row.native_avg:.4f}" if row.native_avg is not None else "N/A"
        bench = BENCHMARKS.get(row.name)
        desc = bench.description if bench else ""
        print(f"{row.name:<25} {row.unit:<8} {val_str:>12}  {desc}")

    print("=" * 60)
    print()


# ── Path Resolution ────────────────────────────────────────────────────────

def build_litebox_binaries(
    workspace_root: Path, release: bool,
) -> tuple[Path, Path]:
    """
    Build litebox_runner_linux_userland and litebox_packager via cargo.

    Returns (runner_path, packager_path).
    """
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
    workspace_root: Path, release: bool,
) -> tuple[Optional[Path], Optional[Path]]:
    """Find pre-built litebox binaries without building."""
    build_type = "release" if release else "debug"
    runner = workspace_root / "target" / build_type / "litebox_runner_linux_userland"
    packager = workspace_root / "target" / build_type / "litebox_packager"
    return (
        runner if runner.exists() else None,
        packager if packager.exists() else None,
    )


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run LMbench benchmarks natively and under LiteBox, then compare results.",
    )
    parser.add_argument(
        "--benchmarks", nargs="+", default=DEFAULT_BENCHMARKS,
        choices=list(BENCHMARKS.keys()),
        help="Which benchmarks to run (default: all supported)",
    )
    parser.add_argument(
        "--mode", choices=["both", "native", "litebox"], default="native",
        help="Run mode: 'native', 'litebox', or 'both' "
             "(default: native, since all LMbench benchmarks require fork)",
    )
    parser.add_argument(
        "--repetitions", type=int, default=None,
        help="Override -N <repetitions> for all benchmarks "
             "(default: use per-benchmark defaults)",
    )
    parser.add_argument(
        "--iterations", type=int, default=1,
        help="Number of times to run each benchmark (for averaging) "
             "(default: 1)",
    )
    parser.add_argument(
        "--release", action="store_true",
        help="Use release build of litebox binaries",
    )
    parser.add_argument(
        "--runner-path", type=str, default=None,
        help="Path to litebox_runner_linux_userland binary (auto-detected if not given)",
    )
    parser.add_argument(
        "--packager-path", type=str, default=None,
        help="Path to litebox_packager binary (auto-detected if not given)",
    )
    parser.add_argument(
        "--no-build", action="store_true",
        help="Skip building litebox binaries (use existing binaries as-is)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Save results to a JSON file",
    )
    parser.add_argument(
        "--work-dir", type=str, default=None,
        help="Working directory for intermediate files (default: temp dir)",
    )

    args = parser.parse_args()

    workspace_root = find_workspace_root()

    # ── Download and build LMbench ──────────────────────────────────────

    ensure_lmbench_downloaded(workspace_root)
    lmbench_dir = find_lmbench_dir(workspace_root)
    bin_dir = ensure_lmbench_built(lmbench_dir)

    # ── Resolve litebox binaries ────────────────────────────────────────

    run_litebox_mode = args.mode in ("both", "litebox")
    runner_path = None
    packager_path = None

    if run_litebox_mode:
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
                print("Run without --no-build, or build manually:")
                print("  cargo build -p litebox_runner_linux_userland"
                      + (" --release" if args.release else ""))
                sys.exit(1)
        else:
            runner_path, packager_path = build_litebox_binaries(
                workspace_root, args.release,
            )

    # ── Working directory ───────────────────────────────────────────────

    if args.work_dir:
        work_dir = Path(args.work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        cleanup_work_dir = False
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="litebox_lmbench_"))
        cleanup_work_dir = True

    # ── Print configuration ─────────────────────────────────────────────

    print(f"Workspace root:  {workspace_root}")
    print(f"LMbench dir:     {lmbench_dir}")
    print(f"LMbench bin dir: {bin_dir}")
    print(f"Work dir:        {work_dir}")
    if run_litebox_mode:
        print(f"Runner:          {runner_path}")
        print(f"Packager:        {packager_path or 'cargo run'}")
    print(f"Benchmarks:      {', '.join(args.benchmarks)}")
    if args.repetitions is not None:
        print(f"Repetitions:     {args.repetitions} (override)")
    else:
        print(f"Repetitions:     per-benchmark defaults")
    print(f"Iterations:      {args.iterations}")
    print(f"Mode:            {args.mode}")
    print()

    # ── Run benchmarks ──────────────────────────────────────────────────

    all_results: dict[str, ComparisonRow] = {}

    for bench_name in args.benchmarks:
        bench = BENCHMARKS[bench_name]
        row = ComparisonRow(
            name=bench_name,
            unit=bench.default_unit,
            higher_is_better=bench.higher_is_better,
        )

        reps = args.repetitions if args.repetitions is not None else bench.default_repetitions

        # Native runs
        if args.mode in ("both", "native"):
            print(f"[Native] {bench_name} ({args.iterations} iteration(s), -N {reps})")
            for i in range(args.iterations):
                if args.iterations > 1:
                    print(f"  Iteration {i + 1}/{args.iterations}")
                result = run_native(bin_dir, bench, reps)
                if result:
                    row.native_values.append(result.value)
                    row.unit = result.unit
                    print(f"    Result: {result.value:.4f} {result.unit}")

        # LiteBox runs
        if run_litebox_mode:
            if bench.requires_fork:
                print(f"[LiteBox] {bench_name}: "
                      f"SKIPPED (requires fork, not yet supported in LiteBox)")
            else:
                print(f"[LiteBox] {bench_name} ({args.iterations} iteration(s), -N {reps})")
                for i in range(args.iterations):
                    if args.iterations > 1:
                        print(f"  Iteration {i + 1}/{args.iterations}")
                    result = run_litebox(
                        bin_dir, bench, reps,
                        runner_path, work_dir, packager_path,
                    )
                    if result:
                        row.litebox_values.append(result.value)
                        row.unit = row.unit or result.unit
                        print(f"    Result: {result.value:.4f} {result.unit}")

        all_results[bench_name] = row

    # ── Print results ───────────────────────────────────────────────────

    rows = [all_results[name] for name in args.benchmarks if name in all_results]

    if args.mode == "native":
        print_native_table(rows)
    else:
        print_comparison_table(rows)

    # ── Save to JSON ────────────────────────────────────────────────────

    if args.output:
        output_data = {
            "config": {
                "repetitions_override": args.repetitions,
                "iterations": args.iterations,
                "mode": args.mode,
                "benchmarks": args.benchmarks,
            },
            "results": {},
        }
        for name, row in all_results.items():
            output_data["results"][name] = {
                "unit": row.unit,
                "higher_is_better": row.higher_is_better,
                "native_values": row.native_values,
                "litebox_values": row.litebox_values,
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
