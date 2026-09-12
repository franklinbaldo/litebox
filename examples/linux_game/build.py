#!/usr/bin/env python3

# Copyright (c) franklinbaldo.
# Licensed under the MIT license.
"""
build.py - Builds the Linux game for LiteBox on Windows.
Steps:
1. Compiles main.c to static x86_64 Linux musl ELF using zig cc.
2. Rewrites syscalls using litebox_syscall_rewriter.
3. Packages the rewritten binary into target/linux-game/game.tar using explicit mode 0755 and USTAR format.
4. Generates manifest.json with SHA256 hashes of sources, ELF, TAR, runner, runtime diff, and the git commit base.
"""

import os
import sys
import json
import hashlib
import subprocess
import tarfile

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC_C = os.path.join(os.path.dirname(__file__), "main.c")
HOST_PY = os.path.join(os.path.dirname(__file__), "host.py")
BUILD_PY = os.path.join(os.path.dirname(__file__), "build.py")
OUT_DIR = os.path.join(ROOT_DIR, "target", "linux-game")
ELF_OUT = os.path.join(OUT_DIR, "breakout.elf")
HOOKED_OUT = os.path.join(OUT_DIR, "breakout.hooked")
TAR_OUT = os.path.join(OUT_DIR, "game.tar")
MANIFEST_OUT = os.path.join(OUT_DIR, "manifest.json")

REWRITER_BIN = os.path.join(ROOT_DIR, "target", "release", "litebox_syscall_rewriter.exe")
RUNNER_BIN = os.path.join(ROOT_DIR, "target", "release", "litebox_runner_linux_on_windows_userland.exe")


def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_commit():
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception as e:
        print(f"[!] Warning: failed to obtain git commit base: {e}")
        return "unknown"


def get_runtime_diff():
    try:
        res = subprocess.run(
            ["git", "diff", "litebox_platform_windows_userland/src/lib.rs"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=True
        )
        diff_text = res.stdout
        h = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
        return {
            "has_uncommitted_changes": len(diff_text.strip()) > 0,
            "patch_sha256": h,
            "patch_summary": "stdout flush patch in WindowsUserland StdioProvider" if len(diff_text.strip()) > 0 else "clean",
        }
    except Exception as e:
        return {
            "has_uncommitted_changes": False,
            "error": str(e),
        }


def check_prerequisites():
    if not os.path.exists(REWRITER_BIN):
        print(f"ERROR: Syscall rewriter not found at {REWRITER_BIN}")
        print("Please build rewriter first: cargo build --locked --release -p litebox_syscall_rewriter")
        sys.exit(1)
    if not os.path.exists(RUNNER_BIN):
        print(f"ERROR: Runner not found at {RUNNER_BIN}")
        print("Please build runner first: cargo build --locked --release -p litebox_runner_linux_on_windows_userland")
        sys.exit(1)


def compile_c():
    print(f"[*] Compiling {SRC_C} to static Linux x86_64 ELF via zig...")
    os.makedirs(OUT_DIR, exist_ok=True)
    cmd = [
        "uv", "run", "--with", "ziglang==0.13.0",
        "python", "-m", "ziglang", "cc",
        "-target", "x86_64-linux-musl",
        "-static",
        "-O2",
        SRC_C,
        "-o", ELF_OUT
    ]
    subprocess.run(cmd, check=True)
    print(f"[+] Compiled ELF: {ELF_OUT} ({os.path.getsize(ELF_OUT)} bytes)")


def rewrite_syscalls():
    print(f"[*] Rewriting syscalls with {REWRITER_BIN}...")
    cmd = [REWRITER_BIN, ELF_OUT, "-o", HOOKED_OUT]
    subprocess.run(cmd, check=True)
    print(f"[+] Rewritten ELF: {HOOKED_OUT} ({os.path.getsize(HOOKED_OUT)} bytes)")


def package_tar():
    print(f"[*] Packaging tar rootfs to {TAR_OUT} (USTAR format, mode 0755)...")
    with tarfile.open(TAR_OUT, "w", format=tarfile.USTAR_FORMAT) as tar:
        ti = tar.gettarinfo(HOOKED_OUT, arcname="bin/breakout")
        ti.mode = 0o755
        ti.uid = 0
        ti.gid = 0
        ti.uname = "root"
        ti.gname = "root"
        with open(HOOKED_OUT, "rb") as f:
            tar.addfile(ti, f)
    print(f"[+] Created TAR archive: {TAR_OUT} ({os.path.getsize(TAR_OUT)} bytes)")


def generate_manifest():
    commit = get_git_commit()
    runtime_diff = get_runtime_diff()
    manifest = {
        "git_commit_base": commit,
        "runtime_diff": runtime_diff,
        "files": {
            "main_c": {
                "path": os.path.relpath(SRC_C, ROOT_DIR),
                "sha256": compute_sha256(SRC_C),
                "size_bytes": os.path.getsize(SRC_C),
            },
            "host_py": {
                "path": os.path.relpath(HOST_PY, ROOT_DIR),
                "sha256": compute_sha256(HOST_PY),
                "size_bytes": os.path.getsize(HOST_PY),
            },
            "build_py": {
                "path": os.path.relpath(BUILD_PY, ROOT_DIR),
                "sha256": compute_sha256(BUILD_PY),
                "size_bytes": os.path.getsize(BUILD_PY),
            },
            "breakout_elf": {
                "path": os.path.relpath(ELF_OUT, ROOT_DIR),
                "sha256": compute_sha256(ELF_OUT),
                "size_bytes": os.path.getsize(ELF_OUT),
            },
            "breakout_hooked": {
                "path": os.path.relpath(HOOKED_OUT, ROOT_DIR),
                "sha256": compute_sha256(HOOKED_OUT),
                "size_bytes": os.path.getsize(HOOKED_OUT),
            },
            "game_tar": {
                "path": os.path.relpath(TAR_OUT, ROOT_DIR),
                "sha256": compute_sha256(TAR_OUT),
                "size_bytes": os.path.getsize(TAR_OUT),
            },
            "runner_bin": {
                "path": os.path.relpath(RUNNER_BIN, ROOT_DIR),
                "sha256": compute_sha256(RUNNER_BIN),
                "size_bytes": os.path.getsize(RUNNER_BIN),
            },
        }
    }

    with open(MANIFEST_OUT, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Generated build manifest: {MANIFEST_OUT}")


def main():
    check_prerequisites()
    compile_c()
    rewrite_syscalls()
    package_tar()
    generate_manifest()
    print("[+] Build complete! Run with: python examples/linux_game/host.py")


if __name__ == "__main__":
    main()
