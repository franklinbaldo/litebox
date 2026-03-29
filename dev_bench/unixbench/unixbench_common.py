#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Shared utilities for UnixBench benchmark scripts (prepare + run).
"""

import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional


# ── UnixBench source ────────────────────────────────────────────────────────

UNIXBENCH_URL = "https://github.com/kdlucas/byte-unixbench/archive/refs/tags/v6.0.0.zip"
UNIXBENCH_ZIP = "v6.0.0.zip"
UNIXBENCH_EXTRACTED_DIR = "byte-unixbench-6.0.0"

# Maps benchmark name -> binary name in pgms/
BENCHMARK_BINARIES = {
    "dhry2reg": "dhry2reg",
    "whetstone-double": "whetstone-double",
    "execl": "execl",
    "fstime": "fstime",
    "fsbuffer": "fstime",
    "fsdisk": "fstime",
    "pipe": "pipe",
    "syscall": "syscall",
    "context1": "context1",
    "spawn": "spawn",
    "shell1": "looper",
    "shell8": "looper",
}


# ── Workspace / path helpers ───────────────────────────────────────────────

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


def find_unixbench_dir(workspace_root: Path) -> Path:
    """Locate the UnixBench directory."""
    return workspace_root / "dev_bench" / "unixbench" / UNIXBENCH_EXTRACTED_DIR / "UnixBench"


# ── Download / build helpers ───────────────────────────────────────────────

def ensure_unixbench_downloaded(workspace_root: Path) -> None:
    """Download and extract UnixBench if it is not already present."""
    bench_dir = workspace_root / "dev_bench" / "unixbench"
    bench_dir.mkdir(parents=True, exist_ok=True)
    extracted = bench_dir / UNIXBENCH_EXTRACTED_DIR
    if extracted.exists():
        return

    zip_path = bench_dir / UNIXBENCH_ZIP
    if not zip_path.exists():
        print(f"Downloading UnixBench from {UNIXBENCH_URL} ...")
        urllib.request.urlretrieve(UNIXBENCH_URL, str(zip_path))
        print(f"Downloaded to {zip_path}")

    print(f"Extracting {zip_path} ...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(str(bench_dir))
    print(f"Extracted to {extracted}")


def ensure_unixbench_built(unixbench_dir: Path) -> None:
    """Ensure UnixBench is compiled."""
    pgms = unixbench_dir / "pgms"
    if (pgms / "dhry2reg").exists():
        # Ensure shell scripts are executable (zip extraction may lose +x).
        for script in ("multi.sh", "tst.sh"):
            path = pgms / script
            if path.exists():
                path.chmod(path.stat().st_mode | 0o111)
        return
    print("Building UnixBench...")
    result = subprocess.run(["make"], cwd=str(unixbench_dir), capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"Failed to build UnixBench: {stderr[:500]}")
        sys.exit(1)
    # Ensure shell scripts are executable (zip extraction may lose +x).
    for script in ("multi.sh", "tst.sh"):
        path = pgms / script
        if path.exists():
            path.chmod(path.stat().st_mode | 0o111)
    print("UnixBench built successfully.")


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


# ── Tar post-processing ───────────────────────────────────────────────────

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


def add_execl_to_tar(tar_path: Path, rewritten: Path) -> None:
    """
    Add the rewritten binary at ``pgms/execl`` inside the tar for ``execl``
    self-re-exec support.

    Rebuilds the tar from scratch using GNU format to avoid PAX extended
    headers (type ``x``) that ``tar_no_std`` cannot parse, and to avoid the
    issue where appended entries after an end-of-archive marker are invisible.
    """
    rebuilt_path = tar_path.with_suffix(".rebuilt.tar")
    with tarfile.open(rebuilt_path, "w", format=tarfile.GNU_FORMAT) as out_tf:
        with tarfile.open(tar_path) as in_tf:
            for member in in_tf.getmembers():
                out_tf.addfile(member, in_tf.extractfile(member))
        out_tf.add(str(rewritten), arcname="pgms/execl")
    rebuilt_path.rename(tar_path)


# System utilities required by shell benchmarks (multi.sh, tst.sh).
SHELL_UTILITIES = ["sort", "od", "grep", "tee", "wc", "rm", "cat"]


def add_shell_support_to_tar(
    tar_path: Path,
    pgms_dir: Path,
    unixbench_dir: Path,
    packager_path: Optional[Path],
    work_dir: Path,
) -> bool:
    """
    Add /bin/sh, system utilities, shell scripts, and data files to the
    rootfs tar for shell benchmarks (shell1/shell8).

    The packager rewrites each system binary (and its shared libraries)
    into its own tar.  This function merges all of those into the main
    benchmark rootfs tar, deduplicating shared library entries.

    Returns True on success, False on failure.
    """
    import io
    import shutil as _shutil

    # 1. Find /bin/sh (resolve symlink to actual binary, e.g. dash/bash)
    sh_path = _shutil.which("sh")
    if sh_path is None:
        print("  Error: /bin/sh not found")
        return False
    sh_real = Path(sh_path).resolve()

    # 2. Collect all binaries to rewrite
    bins_to_rewrite: list[Path] = [sh_real]
    for util in SHELL_UTILITIES:
        util_path = _shutil.which(util)
        if util_path is None:
            print(f"  Error: {util} not found in PATH")
            return False
        bins_to_rewrite.append(Path(util_path).resolve())

    # Deduplicate (e.g. if sh and bash are the same binary)
    bins_to_rewrite = list(dict.fromkeys(bins_to_rewrite))

    # 3. Rewrite each binary with the packager and collect the tar outputs
    rewritten_tars: list[Path] = []
    for binary in bins_to_rewrite:
        bin_tar = work_dir / f"rootfs_{binary.name}.tar"
        if packager_path:
            cmd = [str(packager_path)]
        else:
            cmd = ["cargo", "run", "-p", "litebox_packager", "--"]
        cmd += [str(binary), "-o", str(bin_tar)]
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            print(f"  Error: packager failed for {binary.name}: {stderr[:500]}")
            return False
        rewritten_tars.append(bin_tar)

    # 4. Merge all rewritten binaries into the main tar.
    rebuilt_path = tar_path.with_suffix(".shell.tar")
    with tarfile.open(rebuilt_path, "w", format=tarfile.GNU_FORMAT) as out_tf:
        # Copy existing entries from the main tar
        seen: set[str] = set()
        with tarfile.open(tar_path) as in_tf:
            for member in in_tf.getmembers():
                seen.add(member.name)
                out_tf.addfile(member, in_tf.extractfile(member))

        # Merge entries from each utility's tar (deduplicate shared libs)
        for util_tar in rewritten_tars:
            with tarfile.open(util_tar) as in_tf:
                for member in in_tf.getmembers():
                    if member.name not in seen:
                        seen.add(member.name)
                        fileobj = in_tf.extractfile(member)
                        out_tf.addfile(member, fileobj)

        # 5. Add /bin/sh as a copy of the rewritten shell binary.
        # The packager stores the rewritten shell at its real path
        # (e.g. usr/bin/dash).  We need bin/sh for #! /bin/sh resolution.
        sh_in_tar = str(sh_real).lstrip("/")
        sh_data = None
        for util_tar in rewritten_tars[:1]:  # first tar is always the shell
            with tarfile.open(util_tar) as in_tf:
                for member in in_tf.getmembers():
                    if member.name == sh_in_tar:
                        sh_data = in_tf.extractfile(member).read()
                        break
            if sh_data is not None:
                break

        if sh_data is not None and "bin/sh" not in seen:
            sh_member = tarfile.TarInfo(name="bin/sh")
            sh_member.size = len(sh_data)
            sh_member.mode = 0o755
            out_tf.addfile(sh_member, io.BytesIO(sh_data))
            seen.add("bin/sh")

        # 6. Add shell scripts from pgms/
        for script in ("multi.sh", "tst.sh"):
            script_path = pgms_dir / script
            if script_path.exists() and f"pgms/{script}" not in seen:
                out_tf.add(str(script_path), arcname=f"pgms/{script}")
                seen.add(f"pgms/{script}")

        # 7. Add sort.src data file at the root (CWD is / in the sandbox).
        sort_src = unixbench_dir / "testdir" / "sort.src"
        if sort_src.exists() and "sort.src" not in seen:
            out_tf.add(str(sort_src), arcname="sort.src")
            seen.add("sort.src")

    rebuilt_path.rename(tar_path)
    return True
