#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Shared utilities for LMbench benchmark scripts (prepare + run).
"""

import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional


# ── LMbench source ─────────────────────────────────────────────────────────

LMBENCH_URL = "https://github.com/intel/lmbench/archive/refs/heads/master.zip"
LMBENCH_ZIP = "lmbench-master.zip"
LMBENCH_EXTRACTED_DIR = "lmbench-master"

# Maps benchmark name -> binary name in bin/<os>/
BENCHMARK_BINARIES = {
    "lat_syscall_null": "lat_syscall",
    "lat_syscall_read": "lat_syscall",
    "lat_syscall_write": "lat_syscall",
    "lat_syscall_stat": "lat_syscall",
    "lat_syscall_fstat": "lat_syscall",
    "lat_syscall_open": "lat_syscall",
    "lat_sig_install": "lat_sig",
    "lat_sig_catch": "lat_sig",
    "lat_sig_prot": "lat_sig",
    "lat_pipe": "lat_pipe",
    "lat_proc_fork": "lat_proc",
    "lat_proc_exec": "lat_proc",
    "lat_proc_shell": "lat_proc",
    "lat_ctx": "lat_ctx",
    "bw_mem_rd": "bw_mem",
    "bw_mem_wr": "bw_mem",
    "bw_mem_cp": "bw_mem",
    "bw_mem_bzero": "bw_mem",
    "bw_pipe": "bw_pipe",
    "bw_unix": "bw_unix",
}


# ── Workspace / path helpers ──────────────────────────────────────────────

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
    return script_dir.parent


def find_lmbench_dir(workspace_root: Path) -> Path:
    """Locate the LMbench source directory."""
    return workspace_root / "dev_bench" / "lmbench" / LMBENCH_EXTRACTED_DIR


def find_bin_dir(lmbench_dir: Path) -> Optional[Path]:
    """
    Locate the LMbench bin directory (auto-detected OS platform).

    After building, binaries are placed in ``bin/<os>/`` where ``<os>``
    is detected by the ``scripts/os`` script (e.g. ``x86_64-linux-gnu``).
    """
    bin_base = lmbench_dir / "bin"
    if not bin_base.exists():
        return None
    for d in sorted(bin_base.iterdir()):
        if d.is_dir() and (d / "lat_syscall").exists():
            return d
    return None


# ── Download / build helpers ──────────────────────────────────────────────

def ensure_lmbench_downloaded(workspace_root: Path) -> None:
    """Download and extract LMbench if it is not already present."""
    bench_dir = workspace_root / "dev_bench" / "lmbench"
    bench_dir.mkdir(parents=True, exist_ok=True)
    extracted = bench_dir / LMBENCH_EXTRACTED_DIR
    if extracted.exists():
        return

    zip_path = bench_dir / LMBENCH_ZIP
    if not zip_path.exists():
        print(f"Downloading LMbench from {LMBENCH_URL} ...")
        urllib.request.urlretrieve(LMBENCH_URL, str(zip_path))
        print(f"Downloaded to {zip_path}")

    print(f"Extracting {zip_path} ...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(str(bench_dir))
    print(f"Extracted to {extracted}")


def ensure_lmbench_built(lmbench_dir: Path) -> Path:
    """
    Ensure LMbench is compiled.  Returns the bin directory containing
    the benchmark executables.
    """
    bin_dir = find_bin_dir(lmbench_dir)
    if bin_dir is not None:
        return bin_dir

    src_dir = lmbench_dir / "src"
    scripts_dir = lmbench_dir / "scripts"

    # Ensure scripts are executable (zip extraction may lose +x).
    if scripts_dir.exists():
        for f in scripts_dir.iterdir():
            if f.is_file():
                f.chmod(f.stat().st_mode | 0o111)

    print("Building LMbench ...")
    result = subprocess.run(
        ["make"],
        cwd=str(src_dir),
        capture_output=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        # Some targets (e.g. lat_rpc) may fail due to missing headers,
        # but the core benchmarks should still be built.
        print(f"Warning: LMbench build had issues (exit {result.returncode})")
        print(f"  stderr (last 500 chars): ...{stderr[-500:]}")

    bin_dir = find_bin_dir(lmbench_dir)
    if bin_dir is None:
        print("Error: no LMbench binaries found after build.")
        print("  Ensure gcc, make, and libc-dev are installed.")
        sys.exit(1)

    print(f"LMbench built successfully.  Binaries in {bin_dir}")
    return bin_dir


def build_packager(workspace_root: Path, release: bool) -> Path:
    """Build litebox_packager and return its path."""
    build_type = "release" if release else "debug"
    cmd = ["cargo", "build", "-p", "litebox_packager"]
    if release:
        cmd.append("--release")

    print(f"Building litebox_packager ({build_type})...")
    result = subprocess.run(cmd, cwd=str(workspace_root))
    if result.returncode != 0:
        print(f"Error: cargo build failed (exit {result.returncode})")
        sys.exit(1)

    packager = workspace_root / "target" / build_type / "litebox_packager"
    assert packager.exists(), f"Packager not found at {packager}"
    print("Build complete.")
    return packager


# ── Tar post-processing ──────────────────────────────────────────────────

def extract_rewritten_binary(
    tar_path: Path, binary: Path, output_path: Path,
) -> None:
    """Extract the rewritten main binary from a packager-produced tar."""
    binary_in_tar = str(binary.resolve()).lstrip("/")
    with tarfile.open(tar_path) as tf:
        member = tf.extractfile(tf.getmember(binary_in_tar))
        if member is None:
            raise RuntimeError(f"could not extract {binary_in_tar} from tar")
        output_path.write_bytes(member.read())
    output_path.chmod(0o755)
