#!/usr/bin/env python3

# Copyright (c) franklinbaldo.
# Licensed under the MIT license.

"""Run the SDL video integration with a process-wide timeout and captured logs."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tar", type=Path)
    parser.add_argument("--hold-seconds", type=int, default=2, choices=range(2, 31))
    parser.add_argument("--input-probe", action="store_true")
    parser.add_argument("--focus-release", action="store_true")
    args = parser.parse_args()
    tar = args.tar.resolve(strict=True)
    out = ROOT / "target/sdl-video-validation"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cargo", "build", "--locked", "-p", "litebox_runner_linux_on_windows_userland",
                    "--example", "sdl_video_probe"], cwd=ROOT, check=True, timeout=180)
    env = dict(os.environ, LITEBOX_VIDEO_HOLD_SECS=str(args.hold_seconds))
    env.pop("LITEBOX_INPUT_PROBE", None)
    env.pop("LITEBOX_FOCUS_PROBE", None)
    if args.input_probe or args.focus_release:
        env["LITEBOX_INPUT_PROBE"] = "1"
    if args.focus_release:
        env["LITEBOX_FOCUS_PROBE"] = "1"
    try:
        result = subprocess.run([str(ROOT / "target/debug/examples/sdl_video_probe.exe"), str(tar), str(out / "frame.ppm")],
                                env=env, cwd=ROOT, capture_output=True, timeout=args.hold_seconds+20)
    except subprocess.TimeoutExpired as error:
        (out / "stdout.log").write_bytes(error.stdout or b"")
        (out / "stderr.log").write_bytes(error.stderr or b"")
        print((error.stdout or b"").decode(errors="replace"))
        print((error.stderr or b"").decode(errors="replace"))
        raise
    (out / "stdout.log").write_bytes(result.stdout)
    (out / "stderr.log").write_bytes(result.stderr)
    print(result.stdout.decode(errors="replace"))
    print(result.stderr.decode(errors="replace"))
    result.check_returncode()
    assert b"SDL_VIDEO_OK: 3 verified frames" in result.stdout, result.stdout
    if args.input_probe or args.focus_release:
        assert b"SDL_KEYDOWN_RIGHT_OK" in result.stdout, result.stdout
        assert b"SDL_KEYUP_RIGHT_OK" in result.stdout, result.stdout

if __name__ == "__main__":
    main()
