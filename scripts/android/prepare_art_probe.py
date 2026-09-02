#!/usr/bin/env python3
"""Add a caller-built dex/jar fixture to an Android runtime TAR."""
from __future__ import annotations

import argparse
import pathlib
import tarfile
import tempfile
import shutil

GUEST_ARTIFACT = "data/local/tmp/litebox-art-probe.jar"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--runtime-tar", type=pathlib.Path, required=True)
    p.add_argument("--artifact", type=pathlib.Path, required=True, help="dex-containing jar produced by d8")
    p.add_argument("--output", type=pathlib.Path, required=True)
    args = p.parse_args()

    if not args.runtime_tar.is_file():
        raise SystemExit("runtime TAR not found")
    if not args.artifact.is_file():
        raise SystemExit("ART probe artifact not found")

    with tempfile.TemporaryDirectory(prefix="litebox-art-probe-") as td:
        root = pathlib.Path(td)
        with tarfile.open(args.runtime_tar, "r") as src:
            src.extractall(root, filter="data")
        target = root / GUEST_ARTIFACT
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.artifact, target)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.output, "w") as out:
            for path in sorted(root.rglob("*")):
                out.add(path, arcname=path.relative_to(root), recursive=False)

    print(f"guest_artifact=/{GUEST_ARTIFACT}")
    print(f"bundle={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
