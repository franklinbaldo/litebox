#!/usr/bin/env python3
"""Build a bounded Android userspace TAR from an extracted x86_64 AOSP tree.

This tool copies only explicitly requested guest paths plus their ELF DT_NEEDED
closure. It never packages an entire Android image implicitly.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

DEFAULT_LIBRARY_DIRS = (
    "/system/lib64",
    "/system_ext/lib64",
    "/product/lib64",
    "/vendor/lib64",
    "/apex/com.android.runtime/lib64/bionic",
    "/apex/com.android.art/lib64",
)


def run(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def needed(readelf: str, binary: pathlib.Path) -> list[str]:
    output = run(readelf, "-d", str(binary))
    result: list[str] = []
    for line in output.splitlines():
        if "(NEEDED)" in line and "[" in line:
            result.append(line.rsplit("[", 1)[1].rstrip("]"))
    return result


def is_elf(path: pathlib.Path) -> bool:
    try:
        return path.read_bytes()[:4] == b"\x7fELF"
    except OSError:
        return False


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def guest_host(root: pathlib.Path, guest_path: str) -> pathlib.Path:
    return root / guest_path.lstrip("/")


def resolve_library(root: pathlib.Path, soname: str, library_dirs: tuple[str, ...]) -> str:
    candidates = [d.rstrip("/") + "/" + soname for d in library_dirs]
    existing = [p for p in candidates if guest_host(root, p).exists()]
    if not existing:
        raise SystemExit(f"missing Android dependency {soname}; searched: {', '.join(candidates)}")
    # Android may expose the same SONAME in several partitions/APEXes. Silent
    # guessing makes the bundle non-reproducible, so require a unique match.
    if len(existing) != 1:
        raise SystemExit(f"ambiguous Android dependency {soname}: {', '.join(existing)}")
    return existing[0]


def copy_guest(root: pathlib.Path, staging: pathlib.Path, guest_path: str) -> pathlib.Path:
    src = guest_host(root, guest_path)
    if not src.exists():
        raise SystemExit(f"missing guest path: {guest_path}")
    dst = guest_host(staging, guest_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_symlink():
        dst.symlink_to(os.readlink(src))
    else:
        shutil.copy2(src, dst)
    return src


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--android-root", type=pathlib.Path, required=True)
    p.add_argument("--entry", action="append", required=True, help="absolute guest path; repeatable")
    p.add_argument("--extra", action="append", default=[], help="extra absolute guest path; repeatable")
    p.add_argument("--lib-dir", action="append", default=[])
    p.add_argument("--readelf", default=os.environ.get("READELF", "llvm-readelf"))
    p.add_argument("--output", type=pathlib.Path, required=True)
    args = p.parse_args()

    root = args.android_root.resolve()
    library_dirs = tuple(args.lib_dir) if args.lib_dir else DEFAULT_LIBRARY_DIRS
    pending = list(dict.fromkeys(args.entry + args.extra))
    copied: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="litebox-android-runtime-") as td:
        staging = pathlib.Path(td)
        while pending:
            guest_path = pending.pop(0)
            if guest_path in copied:
                continue
            host_path = copy_guest(root, staging, guest_path)
            copied.add(guest_path)
            if host_path.is_file() and is_elf(host_path):
                for soname in needed(args.readelf, host_path):
                    dep = resolve_library(root, soname, library_dirs)
                    if dep not in copied:
                        pending.append(dep)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.output, "w") as tf:
            for path in sorted(staging.rglob("*")):
                tf.add(path, arcname=path.relative_to(staging), recursive=False)

    print(f"bundle={args.output}")
    print(f"sha256={sha256(args.output)}")
    for path in sorted(copied):
        print(f"included={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
