#!/usr/bin/env python3

# Copyright (c) franklinbaldo.
# Licensed under the MIT license.

"""Build externally with the Breakout toolchain; run a bounded real-guest probe."""
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "target" / "desktop-pipe-probe"

def run(args, timeout=180):
    return subprocess.run([str(x) for x in args], cwd=ROOT, check=True, timeout=timeout)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    run(["uv", "run", "--with", "ziglang==0.13.0", "python", "-m", "ziglang", "cc",
         "-target", "x86_64-linux-musl", "-static", "-O2", Path(__file__).with_name("main.c"),
         "-o", OUT / "probe.elf"])
    run(["cargo", "build", "--locked", "-p", "litebox_syscall_rewriter", "-p",
         "litebox_runner_linux_on_windows_userland", "--example", "desktop_pipe_probe"])
    # Build the rewriter binary explicitly because --example selects examples only.
    run(["cargo", "build", "--locked", "-p", "litebox_syscall_rewriter"])
    run([ROOT / "target/debug/litebox_syscall_rewriter.exe", OUT / "probe.elf", "-o", OUT / "probe.hooked"])
    with tarfile.open(OUT / "probe.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        info = tar.gettarinfo(str(OUT / "probe.hooked"), arcname="bin/probe")
        info.mode, info.uid, info.gid, info.mtime = 0o755, 0, 0, 0
        with (OUT / "probe.hooked").open("rb") as data:
            tar.addfile(info, data)
    result = subprocess.run([str(ROOT / "target/debug/examples/desktop_pipe_probe.exe"), str(OUT / "probe.tar")],
                            cwd=ROOT, capture_output=True, timeout=15, check=True)
    assert b"GUEST_STDOUT_OK" in result.stdout, result
    assert b"DESKTOP_PIPE_OK" in result.stdout, result
    print(result.stdout.decode())

if __name__ == "__main__":
    main()
