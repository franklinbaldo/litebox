#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Run SQLite speedtest1 benchmark natively and under LiteBox, then compare.

SQLite's official speedtest1 exercises mmap, file I/O, and compute together.
Statically compiled — no runtime dependencies needed.

Usage:
    python3 run_sqlite.py [options]

Examples:
    # Run both native and LiteBox with default settings (in-memory)
    python3 run_sqlite.py --release

    # Run only native
    python3 run_sqlite.py --mode native

    # Run only LiteBox
    python3 run_sqlite.py --mode litebox --release

    # Override iterations
    python3 run_sqlite.py --iterations 5 --release

    # Use a specific size multiplier (default: 100)
    python3 run_sqlite.py --size 200 --release

    # Use file-backed database instead of :memory:
    python3 run_sqlite.py --no-memory --release

    # Save results to JSON
    python3 run_sqlite.py --release --output results.json
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
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── SQLite source configuration ─────────────────────────────────────────────

SQLITE_VERSION = "3510300"  # 3.51.3
SQLITE_YEAR = "2026"
SQLITE_SRC_URL = (
    f"https://www.sqlite.org/{SQLITE_YEAR}/sqlite-src-{SQLITE_VERSION}.zip"
)
SQLITE_SRC_ZIP = f"sqlite-src-{SQLITE_VERSION}.zip"
SQLITE_SRC_DIR = f"sqlite-src-{SQLITE_VERSION}"


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


def find_sqlite_dir(workspace_root: Path) -> Path:
    """Return the path to the SQLite source directory under dev_bench/sqlite/."""
    return workspace_root / "dev_bench" / "sqlite" / SQLITE_SRC_DIR


# ── SQLite Download & Build ─────────────────────────────────────────────────


def ensure_sqlite_downloaded(workspace_root: Path) -> Path:
    """Download and extract SQLite source if not already present."""
    sqlite_dir = find_sqlite_dir(workspace_root)
    if sqlite_dir.exists():
        return sqlite_dir

    script_dir = workspace_root / "dev_bench" / "sqlite"
    zip_path = script_dir / SQLITE_SRC_ZIP

    if not zip_path.exists():
        print(f"Downloading SQLite source from {SQLITE_SRC_URL}...")
        urllib.request.urlretrieve(SQLITE_SRC_URL, str(zip_path))
        print("Download complete.")

    print(f"Extracting {SQLITE_SRC_ZIP}...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(script_dir)
    print("Extraction complete.")

    # Zip files don't preserve Unix execute bits. Restore them for scripts
    # that configure/make will need.
    for pattern in ("configure", "config.sub", "config.guess", "install-sh"):
        for p in sqlite_dir.rglob(pattern):
            p.chmod(p.stat().st_mode | 0o755)
    for p in sqlite_dir.rglob("*.sh"):
        p.chmod(p.stat().st_mode | 0o755)
    # autosetup helper scripts (used by newer SQLite versions)
    autosetup = sqlite_dir / "autosetup"
    if autosetup.is_dir():
        for p in autosetup.iterdir():
            if p.is_file():
                p.chmod(p.stat().st_mode | 0o755)

    assert sqlite_dir.exists(), (
        f"Expected directory {sqlite_dir} not found after extraction"
    )
    return sqlite_dir


def ensure_speedtest1_built(sqlite_dir: Path) -> Path:
    """Build speedtest1 statically from SQLite source."""
    speedtest1 = sqlite_dir / "speedtest1"
    if speedtest1.exists():
        return speedtest1

    sqlite3_c = sqlite_dir / "sqlite3.c"
    speedtest1_c = sqlite_dir / "test" / "speedtest1.c"

    # The amalgamation (sqlite3.c) may need to be generated from the source tree.
    if not sqlite3_c.exists():
        print("Generating SQLite amalgamation (configure && make sqlite3.c)...")
        subprocess.run(
            ["./configure", "--disable-tcl", "--disable-readline"],
            cwd=str(sqlite_dir),
            check=True,
        )
        subprocess.run(
            ["make", "sqlite3.c"],
            cwd=str(sqlite_dir),
            check=True,
        )

    assert sqlite3_c.exists(), f"sqlite3.c not found at {sqlite3_c}"
    assert speedtest1_c.exists(), f"speedtest1.c not found at {speedtest1_c}"

    print("Building speedtest1 (static)...")
    compile_cmd = [
        "gcc",
        "-O2",
        "-DSQLITE_THREADSAFE=0",
        "-DSQLITE_OMIT_LOAD_EXTENSION",
        "-DSQLITE_ENABLE_RTREE",
        "-I",
        str(sqlite_dir),
        str(sqlite3_c),
        str(speedtest1_c),
        "-o",
        str(speedtest1),
        "-static",
        "-lpthread",
        "-lm",
    ]
    result = subprocess.run(compile_cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"Error: compilation failed:\n{stderr}")
        sys.exit(1)

    print("Build complete.")
    assert speedtest1.exists(), f"speedtest1 binary not found at {speedtest1}"
    return speedtest1


# ── Result Parsing ──────────────────────────────────────────────────────────


@dataclass
class SubtestResult:
    """A single subtest line from speedtest1 output."""

    testset: str  # e.g. "main", "orm", "cte", ...
    id: str  # e.g. "100", "110"
    description: str  # e.g. "50000 INSERTs into table with no index"
    seconds: float


@dataclass
class BenchmarkResult:
    """Parsed result from a single speedtest1 run."""

    total_seconds: float
    elapsed: float  # wall-clock seconds
    subtests: list[SubtestResult] = field(default_factory=list)
    raw_output: str = ""

    def to_dict(self) -> dict:
        return {
            "total_seconds": self.total_seconds,
            "elapsed": self.elapsed,
            "subtests": [
                {
                    "testset": s.testset,
                    "id": s.id,
                    "description": s.description,
                    "seconds": s.seconds,
                }
                for s in self.subtests
            ],
        }


def parse_speedtest1_output(output: str) -> Optional[tuple[float, list[SubtestResult]]]:
    """
    Parse speedtest1 output: individual subtests and the TOTAL.

    Returns (total_seconds, list_of_subtests) or None if no TOTAL found.

    Output lines look like:
     100 - 50000 INSERTs into table with no index......   0.033s
           Begin testset "orm"
     100 - Fill 250 rows...............................   0.052s
           TOTAL.......................................   4.285s
    """
    total = 0.0
    found_total = False
    subtests: list[SubtestResult] = []
    current_testset = "main"

    for line in output.splitlines():
        # Testset header: e.g. '       Begin testset "orm"'
        m_ts = re.search(r'Begin testset "(\w+)"', line)
        if m_ts:
            current_testset = m_ts.group(1)
            continue

        # TOTAL line
        m_total = re.search(r"TOTAL[.\s]+([0-9.]+)s", line)
        if m_total:
            total += float(m_total.group(1))
            found_total = True
            continue

        # Subtest line: e.g. ' 100 - 50000 INSERTs into table......  0.033s'
        m_sub = re.match(r"\s*(\d+) - (.+?)\.{2,}\s+([0-9.]+)s", line)
        if m_sub:
            subtests.append(SubtestResult(
                testset=current_testset,
                id=m_sub.group(1),
                description=m_sub.group(2).strip(),
                seconds=float(m_sub.group(3)),
            ))

    return (total, subtests) if found_total else None


# ── Native Runner ───────────────────────────────────────────────────────────


def run_native(
    speedtest1_path: Path,
    size: int,
    use_memory: bool,
) -> Optional[BenchmarkResult]:
    """Run speedtest1 natively."""
    cmd = [str(speedtest1_path), "--size", str(size)]
    if use_memory:
        cmd.append("--memdb")

    print(f"  Running: {' '.join(cmd)}")
    t0 = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=600)
    except subprocess.TimeoutExpired:
        print("  [TIMEOUT]")
        return None
    elapsed = time.monotonic() - t0

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        stdout = result.stdout.decode("utf-8", errors="replace")
        print(f"  [FAIL] exit code {result.returncode}")
        print(f"  stderr: {stderr[:500]}")
        print(f"  stdout: {stdout[:500]}")
        return None

    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    parsed = parse_speedtest1_output(stdout)
    if parsed is None:
        parsed = parse_speedtest1_output(stderr)
    if parsed is None:
        print(f"  [FAIL] no TOTAL line in output:\n{(stdout + stderr)[:500]}")
        return None

    total, subtests = parsed
    return BenchmarkResult(
        total_seconds=total,
        elapsed=elapsed,
        subtests=subtests,
        raw_output=stdout,
    )


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
    speedtest1_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[tuple[Path, Path]]:
    """
    Prepare rootfs tar for LiteBox using litebox_packager.

    Since speedtest1 is statically linked, the tar will only contain the
    single rewritten binary.
    """
    tar_path = work_dir / "rootfs_speedtest1.tar"
    rewritten = work_dir / "speedtest1.hooked"

    # Reuse existing tar and rewritten binary if already prepared.
    if tar_path.exists() and rewritten.exists():
        return tar_path, rewritten

    if packager_path:
        cmd = [str(packager_path)]
    else:
        cmd = ["cargo", "run", "-p", "litebox_packager", "--"]

    cmd += [str(speedtest1_path), "-o", str(tar_path)]

    print("  Packaging with litebox_packager...")
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Error: packager failed: {stderr[:500]}")
        return None

    try:
        _extract_rewritten_binary(tar_path, speedtest1_path, rewritten)
    except RuntimeError as e:
        print(f"  Error: {e}")
        return None

    return tar_path, rewritten


def run_litebox(
    speedtest1_path: Path,
    size: int,
    use_memory: bool,
    runner_path: Path,
    work_dir: Path,
    packager_path: Optional[Path],
) -> Optional[BenchmarkResult]:
    """Run speedtest1 under LiteBox."""
    prepared = prepare_litebox_rootfs(speedtest1_path, work_dir, packager_path)
    if prepared is None:
        return None

    tar_path, rewritten = prepared

    cmd = [
        str(runner_path),
        "--unstable",
        "--interception-backend",
        "rewriter",
        "--env",
        "HOME=/",
        "--initial-files",
        str(tar_path),
        str(rewritten),
        "--size",
        str(size),
    ]
    if use_memory:
        cmd.append("--memdb")

    print(f"  Running: {' '.join(cmd)}")
    t0 = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=600)
    except subprocess.TimeoutExpired:
        print("  [TIMEOUT]")
        return None
    elapsed = time.monotonic() - t0

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        stdout = result.stdout.decode("utf-8", errors="replace")
        print(f"  [FAIL] exit code {result.returncode}")
        print(f"  stderr (last 500): ...{stderr[-500:]}")
        print(f"  stdout (last 500): ...{stdout[-500:]}")
        return None

    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    parsed = parse_speedtest1_output(stdout)
    if parsed is None:
        parsed = parse_speedtest1_output(stderr)
    if parsed is None:
        print(f"  [FAIL] no TOTAL line in output:\n{(stdout + stderr)[:500]}")
        return None

    total, subtests = parsed
    return BenchmarkResult(
        total_seconds=total,
        elapsed=elapsed,
        subtests=subtests,
        raw_output=stdout,
    )


# ── Comparison & Reporting ──────────────────────────────────────────────────


@dataclass
class ComparisonRow:
    name: str
    native_times: list[float] = field(default_factory=list)
    litebox_times: list[float] = field(default_factory=list)
    # Subtest-level: keyed by (testset, id, description)
    native_subtests: dict[str, list[float]] = field(default_factory=dict)
    litebox_subtests: dict[str, list[float]] = field(default_factory=dict)

    def record_subtests(self, result: BenchmarkResult, mode: str) -> None:
        """Accumulate per-subtest timings from a run."""
        target = self.native_subtests if mode == "native" else self.litebox_subtests
        for s in result.subtests:
            key = f"{s.testset}/{s.id}"
            target.setdefault(key, []).append(s.seconds)

    @property
    def native_avg(self) -> Optional[float]:
        return (
            sum(self.native_times) / len(self.native_times)
            if self.native_times
            else None
        )

    @property
    def litebox_avg(self) -> Optional[float]:
        return (
            sum(self.litebox_times) / len(self.litebox_times)
            if self.litebox_times
            else None
        )

    @property
    def overhead_pct(self) -> Optional[float]:
        """Overhead percentage. Positive means LiteBox is slower."""
        n = self.native_avg
        lb = self.litebox_avg
        if n and lb and n > 0:
            return ((lb - n) / n) * 100.0
        return None

    @property
    def ratio(self) -> Optional[float]:
        """Time ratio (LiteBox / Native). Values near 1.0 = no overhead."""
        n = self.native_avg
        lb = self.litebox_avg
        if n and lb and n > 0:
            return lb / n
        return None


def print_comparison_table(rows: list[ComparisonRow]):
    """Print formatted comparison table (lower time is better)."""
    print()
    print("=" * 80)
    print(
        f"{'Benchmark':<25} {'Native (s)':>12} {'LiteBox (s)':>12}"
        f" {'Ratio':>8} {'Overhead':>10}"
    )
    print("-" * 80)

    for row in rows:
        native_str = f"{row.native_avg:.3f}" if row.native_avg is not None else "N/A"
        litebox_str = (
            f"{row.litebox_avg:.3f}" if row.litebox_avg is not None else "N/A"
        )
        ratio_str = f"{row.ratio:.4f}" if row.ratio is not None else "N/A"
        overhead_str = (
            f"{row.overhead_pct:+.2f}%" if row.overhead_pct is not None else "N/A"
        )
        print(
            f"{row.name:<25} {native_str:>12} {litebox_str:>12}"
            f" {ratio_str:>8} {overhead_str:>10}"
        )

    print("=" * 80)

    ratios = [r.ratio for r in rows if r.ratio is not None]
    if ratios:
        geo_mean = math.prod(ratios) ** (1.0 / len(ratios))
        print(f"\nGeometric mean time ratio (LiteBox/Native): {geo_mean:.4f}")
        print(f"Overhead: {(geo_mean - 1.0) * 100:+.2f}%")
    print()


def print_subtest_table(row: ComparisonRow) -> None:
    """Print per-subtest comparison table."""
    # Collect all subtest keys in order of first appearance
    all_keys: list[str] = []
    seen: set[str] = set()
    for key in list(row.native_subtests) + list(row.litebox_subtests):
        if key not in seen:
            all_keys.append(key)
            seen.add(key)

    if not all_keys:
        return

    print()
    print("Subtest details:")
    print("=" * 80)
    print(
        f"{'Subtest':<30} {'Native (s)':>12} {'LiteBox (s)':>12}"
        f" {'Ratio':>8} {'Overhead':>10}"
    )
    print("-" * 80)

    for key in all_keys:
        n_list = row.native_subtests.get(key, [])
        l_list = row.litebox_subtests.get(key, [])
        n_avg = sum(n_list) / len(n_list) if n_list else None
        l_avg = sum(l_list) / len(l_list) if l_list else None

        n_str = f"{n_avg:.4f}" if n_avg is not None else "N/A"
        l_str = f"{l_avg:.4f}" if l_avg is not None else "N/A"

        if n_avg and l_avg and n_avg > 0:
            ratio = l_avg / n_avg
            overhead = ((l_avg - n_avg) / n_avg) * 100.0
            r_str = f"{ratio:.4f}"
            o_str = f"{overhead:+.2f}%"
        else:
            r_str = "N/A"
            o_str = "N/A"

        print(
            f"{key:<30} {n_str:>12} {l_str:>12}"
            f" {r_str:>8} {o_str:>10}"
        )

    print("=" * 80)
    print()


# ── Build helpers ───────────────────────────────────────────────────────────


def build_litebox_binaries(
    workspace_root: Path,
    release: bool,
) -> tuple[Path, Path]:
    """Build litebox runner and packager."""
    build_type = "release" if release else "debug"
    cmd = [
        "cargo",
        "build",
        "-p",
        "litebox_runner_linux_userland",
        "-p",
        "litebox_packager",
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


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Run SQLite speedtest1 benchmark natively and under LiteBox.",
    )
    parser.add_argument(
        "--mode",
        choices=["both", "native", "litebox"],
        default="both",
        help="Run mode (default: both)",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=100,
        help="Size multiplier for speedtest1 (default: 100)",
    )
    parser.add_argument(
        "--no-memory",
        action="store_true",
        help="Use file-backed database instead of the default :memory:",
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

    args = parser.parse_args()

    use_memory = not args.no_memory

    workspace_root = find_workspace_root()

    # Download and build SQLite + speedtest1
    sqlite_dir = ensure_sqlite_downloaded(workspace_root)
    speedtest1_path = ensure_speedtest1_built(sqlite_dir)

    # Resolve litebox binaries
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
                workspace_root,
                args.release,
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
                workspace_root,
                args.release,
            )

    # Working directory
    if args.work_dir:
        work_dir = Path(args.work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        cleanup_work_dir = False
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="litebox_sqlite_bench_"))
        cleanup_work_dir = True

    db_label = ":memory:" if use_memory else "file-backed"
    bench_name = f"sqlite-speedtest1({db_label})"

    print(f"Workspace root: {workspace_root}")
    print(f"SQLite dir:     {sqlite_dir}")
    print(f"speedtest1:     {speedtest1_path}")
    print(f"Work dir:       {work_dir}")
    print(f"Database:       {db_label}")
    print(f"Size:           {args.size}")
    print(f"Iterations:     {args.iterations}")
    print(f"Mode:           {args.mode}")
    if run_litebox_mode:
        print(f"Runner:         {runner_path}")
        print(f"Packager:       {packager_path or 'cargo run'}")
    print()

    row = ComparisonRow(name=bench_name)

    # ── Native runs ─────────────────────────────────────────────────────

    if args.mode in ("both", "native"):
        print(f"[Native] {bench_name} (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_native(speedtest1_path, args.size, use_memory)
            if result:
                row.native_times.append(result.total_seconds)
                row.record_subtests(result, "native")
                print(f"    Total: {result.total_seconds:.3f}s")

    # ── LiteBox runs ────────────────────────────────────────────────────

    if run_litebox_mode:
        print(f"[LiteBox] {bench_name} (x{args.iterations} iterations)")
        for i in range(args.iterations):
            print(f"  Iteration {i + 1}/{args.iterations}")
            result = run_litebox(
                speedtest1_path,
                args.size,
                use_memory,
                runner_path,
                work_dir,
                packager_path,
            )
            if result:
                row.litebox_times.append(result.total_seconds)
                row.record_subtests(result, "litebox")
                print(f"    Total: {result.total_seconds:.3f}s")

    # ── Results ─────────────────────────────────────────────────────────

    print_comparison_table([row])
    print_subtest_table(row)

    # ── Save to JSON ────────────────────────────────────────────────────

    if args.output:
        # Build subtest detail for JSON
        all_subtest_keys: list[str] = []
        seen_keys: set[str] = set()
        for key in list(row.native_subtests) + list(row.litebox_subtests):
            if key not in seen_keys:
                all_subtest_keys.append(key)
                seen_keys.add(key)

        subtests_json = {}
        for key in all_subtest_keys:
            n_list = row.native_subtests.get(key, [])
            l_list = row.litebox_subtests.get(key, [])
            n_avg = sum(n_list) / len(n_list) if n_list else None
            l_avg = sum(l_list) / len(l_list) if l_list else None
            subtests_json[key] = {
                "native_times": n_list,
                "litebox_times": l_list,
                "native_avg": n_avg,
                "litebox_avg": l_avg,
            }

        output_data = {
            "config": {
                "size": args.size,
                "database": db_label,
                "iterations": args.iterations,
                "mode": args.mode,
            },
            "results": {
                bench_name: {
                    "native_times": row.native_times,
                    "litebox_times": row.litebox_times,
                    "native_avg": row.native_avg,
                    "litebox_avg": row.litebox_avg,
                    "ratio": row.ratio,
                    "overhead_pct": row.overhead_pct,
                    "subtests": subtests_json,
                },
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
