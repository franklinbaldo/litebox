#!/usr/bin/env python3

# Copyright (c) franklinbaldo.
# Licensed under the MIT license.

"""Exercise native Breakout input, focus loss and window close on Windows.

Development-only dependencies: Pillow. Captures only the test host's window.
Usage: uv run --with pillow python native_input_probe.py --host HOST --runner RUNNER --tar TAR
"""

import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import subprocess
import time


def main():
    from PIL import ImageGrab

    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "runner", "tar"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("target/desktop-acceptance/input"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    user = C.WinDLL("user32", use_last_error=True)
    enum_callback = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    user.EnumWindows.argtypes = [enum_callback, W.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    user.IsWindowVisible.argtypes = [W.HWND]
    user.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user.SendMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user.SendMessageW.restype = W.LPARAM

    def find_window(pid):
        found = []

        @enum_callback
        def callback(hwnd, _):
            owner = W.DWORD()
            user.GetWindowThreadProcessId(hwnd, C.byref(owner))
            if owner.value == pid and user.IsWindowVisible(hwnd):
                found.append(hwnd)
            return True

        user.EnumWindows(callback, 0)
        return found[0] if found else None

    def paddle(hwnd, label):
        capture = ImageGrab.grab(window=int(hwnd)).convert("RGB")
        capture.save(args.output_dir / (label + ".png"))
        xs = [x for y in range(capture.height * 3 // 4, capture.height)
              for x in range(capture.width)
              if capture.getpixel((x, y)) == (70, 160, 240)]
        if not xs:
            raise AssertionError(f"No paddle pixels in {label}; inspect window capture")
        return sum(xs) / len(xs)

    log_path = args.output_dir / "host.log"
    with log_path.open("w", encoding="utf-8") as log:
        child = subprocess.Popen(
            [str(args.host.resolve()), "--runner", str(args.runner.resolve()),
             "--tar", str(args.tar.resolve()), "--smoke-seconds", "15"],
            stdout=log, stderr=subprocess.STDOUT)
        hwnd = None
        try:
            deadline = time.monotonic() + 5
            hwnd = None
            while time.monotonic() < deadline and child.poll() is None:
                hwnd = find_window(child.pid)
                if hwnd:
                    break
                time.sleep(0.05)
            assert hwnd, "Host did not create a visible window"
            time.sleep(0.4)
            initial = paddle(hwnd, "initial")
            assert user.PostMessageW(hwnd, 0x100, 0x25, 0), "Post left key failed"
            time.sleep(0.2)
            # Focus is a sent message: handling it only in PeekMessage is insufficient.
            user.SendMessageW(hwnd, 0x8, 0, 0)  # WM_KILLFOCUS
            time.sleep(0.12)
            left = paddle(hwnd, "left-focus-lost")
            time.sleep(0.2)
            stopped = paddle(hwnd, "after-focus-lost")
            assert left < initial - 10, (initial, left)
            assert abs(left - stopped) < 10, (left, stopped, "stuck key after focus loss")
            assert user.PostMessageW(hwnd, 0x100, 0x27, 0), "Post right key failed"
            time.sleep(0.3)
            assert user.PostMessageW(hwnd, 0x101, 0x27, 0), "Release right key failed"
            time.sleep(0.12)
            right = paddle(hwnd, "right")
            assert right > stopped + 10, (stopped, right)
            assert user.PostMessageW(hwnd, 0x10, 0, 0), "Post close failed"
            code = child.wait(timeout=5)
            report = {"initial_x": initial, "left_x": left, "focus_stopped_x": stopped,
                      "right_x": right, "host_exit_code": code,
                      "input_and_focus_verified": True}
            (args.output_dir / "result.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2))
            # Smoke mode may classify an early manual close separately; inspect host.log
            # for the actual guest exit code before claiming graceful guest shutdown.
        finally:
            if child.poll() is None:
                if hwnd:
                    user.PostMessageW(hwnd, 0x10, 0, 0)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                   capture_output=True, timeout=5, check=False)
                    child.wait(timeout=5)


if __name__ == "__main__":
    main()
