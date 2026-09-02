#!/usr/bin/env python3
"""Build a minimal Android/bionic LiteBox TAR for RFC #25 M0.

The script is deliberately dependency-light and fail-closed. It does not
compile Android; it verifies and packages caller-supplied x86_64 Android
artifacts after they have been rewritten for LiteBox.
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

ANDROID_INTERPRETERS = {
    "/system/bin/linker64",
    "/apex/com.android.runtime/bin/linker64",
}


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(*argv: str) -> str:
    cp = subprocess.run(argv, check=True, capture_output=True, text=True)
    return cp.stdout


def elf_interpreter(readelf: str, binary: pathlib.Path) -> str:
    output = run(readelf, "-l", str(binary))
    marker = "Requesting program interpreter:"
    for line in output.splitlines():
        if marker in line:
            return line.split(marker, 1)[1].strip().rstrip("]")
    raise SystemExit(f"{binary}: no ELF interpreter found")


def needed(readelf: str, binary: pathlib.Path) -> list[str]:
    output = run(readelf, "-d", str(binary))
    libs: list[str] = []
    for line in output.splitlines():
        if "(NEEDED)" in line and "[" in line:
            libs.append(line.rsplit("[", 1)[1].rstrip("]"))
    return libs


def require_android(binary: pathlib.Path, readelf: str) -> tuple[str, list[str]]:
    interp = elf_interpreter(readelf, binary)
    libs = needed(readelf, binary)
    if interp not in ANDROID_INTERPRETERS:
        allowed = ", ".join(sorted(ANDROID_INTERPRETERS))
        raise SystemExit(f"{binary}: interpreter {interp!r} is not Android; expected one of {allowed}")
    if "libc.so" not in libs:
        raise SystemExit(f"{binary}: libc.so not present in DT_NEEDED; refusing ambiguous M0 fixture")
    return interp, libs


def copy_into(root: pathlib.Path, src: pathlib.Path, guest_path: str) -> None:
    dst = root / guest_path.lstrip("/")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--program", type=pathlib.Path, required=True, help="rewritten Android x86_64 ELF")
    p.add_argument("--linker64", type=pathlib.Path, required=True)
    p.add_argument("--libc", type=pathlib.Path, required=True)
    p.add_argument("--extra-lib", action="append", default=[], type=pathlib.Path)
    p.add_argument("--readelf", default=os.environ.get("READELF", "llvm-readelf"))
    p.add_argument("--output", type=pathlib.Path, required=True)
    args = p.parse_args()

    interp, libs = require_android(args.program, args.readelf)
    if not args.linker64.is_file() or not args.libc.is_file():
        raise SystemExit("linker64/libc path missing")

    with tempfile.TemporaryDirectory(prefix="litebox-android-m0-") as td:
        root = pathlib.Path(td)
        copy_into(root, args.program, "/system/bin/litebox-android-hello")
        copy_into(root, args.linker64, interp)
        copy_into(root, args.libc, "/system/lib64/libc.so")
        for lib in args.extra_lib:
            copy_into(root, lib, f"/system/lib64/{lib.name}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.output, "w") as tf:
            for path in sorted(root.rglob("*")):
                tf.add(path, arcname=path.relative_to(root))

    print(f"program_sha256={sha256(args.program)}")
    print(f"tar_sha256={sha256(args.output)}")
    print(f"interpreter={interp}")
    print("needed=" + ",".join(libs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
