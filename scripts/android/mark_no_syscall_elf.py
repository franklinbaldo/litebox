#!/usr/bin/env python3
"""Mark an ELF as already inspected when the LiteBox rewriter finds no syscalls.

The runtime rewriter uses a 32-byte LITEBOX0 trailer with trampoline_size=0 as
an explicit "checked, nothing to patch" sentinel. This helper invokes the
normal rewriter in a temporary file and accepts the result only when it is
byte-for-byte the original input plus that sentinel. If the rewriter would
actually patch code or cannot inspect the file, the original bytes are
preserved instead.
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import tempfile
from pathlib import Path

MAGIC = b"LITEBOX0"
HEADER_SIZE = 32


def mark_if_syscall_free(path: Path, rewriter: Path) -> bool:
    original = path.read_bytes()
    mode = path.stat().st_mode

    with tempfile.NamedTemporaryFile(delete=False, dir=path.parent) as tmp:
        candidate_path = Path(tmp.name)

    try:
        result = subprocess.run(
            [str(rewriter), str(path), "--output", str(candidate_path)],
            check=False,
        )
        if result.returncode != 0:
            return False

        candidate = candidate_path.read_bytes()
        if len(candidate) != len(original) + HEADER_SIZE:
            return False
        if candidate[:-HEADER_SIZE] != original:
            return False

        header = candidate[-HEADER_SIZE:]
        if header[:8] != MAGIC:
            return False
        file_offset, vaddr, trampoline_size = struct.unpack("<QQQ", header[8:])
        if (file_offset, vaddr, trampoline_size) != (0, 0, 0):
            return False

        path.write_bytes(candidate)
        os.chmod(path, mode)
        return True
    finally:
        candidate_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--rewriter", type=Path, required=True)
    args = parser.parse_args()

    marked = mark_if_syscall_free(args.input, args.rewriter)
    state = "marked syscall-free" if marked else "preserved (rewrite required or unsupported)"
    print(f"{args.input}: {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
