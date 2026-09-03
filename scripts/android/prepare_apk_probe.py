#!/usr/bin/env python3
"""Validate an APK container and inject it into an Android runtime TAR."""
from __future__ import annotations

import argparse
import pathlib
import shutil
import tarfile
import tempfile
import zipfile

GUEST_APK = "data/local/tmp/litebox-apk-smoke.apk"


def validate_apk(path: pathlib.Path) -> list[str]:
    if not zipfile.is_zipfile(path):
        raise SystemExit(f"{path}: not a ZIP/APK container")
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names:
            raise SystemExit(f"{path}: missing AndroidManifest.xml")
        dex = sorted(name for name in names if name.startswith("classes") and name.endswith(".dex"))
        if not dex:
            raise SystemExit(f"{path}: no classes*.dex found")
        return dex


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--runtime-tar", type=pathlib.Path, required=True)
    p.add_argument("--apk", type=pathlib.Path, required=True)
    p.add_argument("--output", type=pathlib.Path, required=True)
    args = p.parse_args()

    dex = validate_apk(args.apk)
    if not args.runtime_tar.is_file():
        raise SystemExit("runtime TAR not found")

    with tempfile.TemporaryDirectory(prefix="litebox-apk-smoke-") as td:
        root = pathlib.Path(td)
        with tarfile.open(args.runtime_tar, "r") as src:
            src.extractall(root, filter="data")
        target = root / GUEST_APK
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.apk, target)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.output, "w", format=tarfile.GNU_FORMAT) as out:
            for path in sorted(root.rglob("*")):
                out.add(path, arcname=path.relative_to(root), recursive=False)

    print(f"guest_apk=/{GUEST_APK}")
    for name in dex:
        print(f"dex={name}")
    print(f"bundle={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
