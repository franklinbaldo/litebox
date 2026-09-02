#!/usr/bin/env python3
"""Finalize an Android runtime TAR for LiteBox execution.

The M1 bundle builder intentionally reasons about Android DT_NEEDED closure. This
step performs the LiteBox-specific AOT syscall rewrite after that closure is
known, and flattens symlinks because the in-memory TAR filesystem does not
support them.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

REWRITE_PREFIXES = ("system/bin/", "system/lib64/")
SKIP_SUFFIXES = (".art", ".oat", ".odex", ".vdex")


def is_elf(path: pathlib.Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def flatten_symlink(root: pathlib.Path, path: pathlib.Path) -> None:
    target = os.readlink(path)
    if os.path.isabs(target):
        resolved = root / target.lstrip("/")
    else:
        resolved = (path.parent / target).resolve(strict=False)
    root_resolved = root.resolve()
    resolved = resolved.resolve()
    if root_resolved not in resolved.parents and resolved != root_resolved:
        raise SystemExit(f"symlink escapes bundle: {path} -> {target}")
    if not resolved.is_file():
        raise SystemExit(f"symlink target missing or non-file: {path} -> {target}")
    mode = resolved.stat().st_mode
    data = resolved.read_bytes()
    path.unlink()
    path.write_bytes(data)
    path.chmod(mode)


def should_rewrite(guest_path: str, path: pathlib.Path) -> bool:
    if guest_path.endswith(SKIP_SUFFIXES):
        return False
    return guest_path.startswith(REWRITE_PREFIXES) and is_elf(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--rewriter", type=pathlib.Path, required=True)
    args = parser.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input TAR not found: {args.input}")
    if not args.rewriter.is_file():
        raise SystemExit(f"LiteBox syscall rewriter not found: {args.rewriter}")

    rewritten: list[str] = []
    with tempfile.TemporaryDirectory(prefix="litebox-android-finalize-") as td:
        root = pathlib.Path(td)
        with tarfile.open(args.input, "r") as source:
            source.extractall(root, filter="data")

        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                flatten_symlink(root, path)

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            guest_path = path.relative_to(root).as_posix()
            if not should_rewrite(guest_path, path):
                continue
            output = path.with_name(path.name + ".litebox-rewritten")
            subprocess.run(
                [str(args.rewriter), str(path), "--output", str(output)],
                check=True,
            )
            mode = path.stat().st_mode
            output.replace(path)
            path.chmod(mode)
            rewritten.append("/" + guest_path)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.output, "w") as dest:
            for path in sorted(root.rglob("*")):
                dest.add(path, arcname=path.relative_to(root), recursive=False)

    if not rewritten:
        raise SystemExit("no Android ELF was rewritten; refusing a false-green bundle")
    print(f"rewritten_count={len(rewritten)}")
    for guest_path in rewritten:
        print(f"rewritten={guest_path}")
    print(f"bundle={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
