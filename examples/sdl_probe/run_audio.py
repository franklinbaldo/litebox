#!/usr/bin/env python3

# Copyright (c) franklinbaldo.
# Licensed under the MIT license.
"""
run_audio.py - Integration harness for SDL2 Linux on Windows Userland Audio Probe.

Validates the full path:
  SDL2 (Linux musl guest) -> LiteBox pipes (FD 5 in, FD 6 out) -> WinMM waveOut (Windows host)

Requirements:
- External timeout with process-isolated kill (kills ONLY its child process).
- Capture exit code and full stdout/stderr logs.
- Parse and count: received, submitted, completed, canceled, errors.
- Validate non-silent PCM evidence, with positive and negative sample evidence.
- Require >= 8 completed buffers, 0 cancellations, 0 errors, clean EOF, and guest exit 0.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DEFAULT_TAR = os.path.join(ROOT_DIR, "target", "sdl-bootstrap", "audio-probe.tar")
DEFAULT_EXE = os.path.join(ROOT_DIR, "target", "debug", "examples", "sdl_audio_probe.exe")
DEFAULT_LOG_DIR = os.path.join(ROOT_DIR, "target", "sdl-audio-validation")


def run_probe(exe_path, tar_path, timeout_sec=10.0, log_dir=DEFAULT_LOG_DIR):
    os.makedirs(log_dir, exist_ok=True)
    stdout_log_path = os.path.join(log_dir, "stdout.log")
    stderr_log_path = os.path.join(log_dir, "stderr.log")
    report_path = os.path.join(log_dir, "report.json")

    if not os.path.exists(exe_path):
        raise FileNotFoundError(f"Probe executable not found: {exe_path}")
    if not os.path.exists(tar_path):
        raise FileNotFoundError(f"Audio probe TAR archive not found: {tar_path}")

    cmd = [exe_path, tar_path]
    print(f"[*] Spawning audio probe: {' '.join(cmd)}")
    print(f"[*] External timeout set to {timeout_sec:.1f}s")

    start_time = time.monotonic()
    timed_out = False

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=ROOT_DIR,
    )

    child_pid = proc.pid
    print(f"[*] Probe child process started with PID {child_pid}")

    try:
        stdout_text, stderr_text = proc.communicate(timeout=timeout_sec)
        return_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        print(f"[!] Timeout expired ({timeout_sec}s). Terminating PID {child_pid}...")
        # Strictly terminate ONLY the child process we spawned
        try:
            proc.kill()
        except OSError:
            pass
        stdout_text, stderr_text = proc.communicate()
        return_code = proc.returncode

    elapsed_sec = time.monotonic() - start_time

    # Save logs
    with open(stdout_log_path, "w", encoding="utf-8") as f:
        f.write(stdout_text)
    with open(stderr_log_path, "w", encoding="utf-8") as f:
        f.write(stderr_text)

    print(f"[*] Probe process exited with code {return_code} in {elapsed_sec:.3f}s")
    if stderr_text:
        print("[*] Stderr snippet:")
        for line in stderr_text.strip().splitlines()[:10]:
            print(f"    {line}")
    if stdout_text:
        print("[*] Stdout snippet:")
        for line in stdout_text.strip().splitlines()[:10]:
            print(f"    {line}")

    # Parse metrics from stdout
    # Expected format:
    # SDL_AUDIO_METRICS: received=9 submitted=9 completed=9 canceled=0 non_silent=8 errors=0 min_sample=-4000 max_sample=4000 has_pos=true has_neg=true guest_exit=0
    # SDL_AUDIO_OK: 9 verified buffers played via WinMM; guest exit 0
    metrics_pattern = re.compile(
        r"SDL_AUDIO_METRICS:\s+"
        r"received=(\d+)\s+"
        r"submitted=(\d+)\s+"
        r"completed=(\d+)\s+"
        r"canceled=(\d+)\s+"
        r"non_silent=(\d+)\s+"
        r"errors=(\d+)\s+"
        r"min_sample=(-?\d+)\s+"
        r"max_sample=(-?\d+)\s+"
        r"has_pos=(true|false)\s+"
        r"has_neg=(true|false)\s+"
        r"guest_exit=(-?\d+)"
    )
    ok_pattern = re.compile(r"SDL_AUDIO_OK:\s+(\d+)\s+verified buffers played via WinMM;\s+guest exit 0")

    metrics_match = metrics_pattern.search(stdout_text)
    ok_match = ok_pattern.search(stdout_text)

    failures = []

    if timed_out:
        failures.append(f"Process timed out after {timeout_sec}s")
    if return_code != 0:
        failures.append(f"Probe host process exited with non-zero code {return_code}")

    parsed_metrics = None
    if metrics_match:
        parsed_metrics = {
            "received": int(metrics_match.group(1)),
            "submitted": int(metrics_match.group(2)),
            "completed": int(metrics_match.group(3)),
            "canceled": int(metrics_match.group(4)),
            "non_silent": int(metrics_match.group(5)),
            "errors": int(metrics_match.group(6)),
            "min_sample": int(metrics_match.group(7)),
            "max_sample": int(metrics_match.group(8)),
            "has_positive": metrics_match.group(9) == "true",
            "has_negative": metrics_match.group(10) == "true",
            "guest_exit": int(metrics_match.group(11)),
        }
    else:
        failures.append("SDL_AUDIO_METRICS line missing or malformed in probe output")

    if not ok_match:
        failures.append("SDL_AUDIO_OK confirmation line missing from probe output")

    if parsed_metrics:
        m = parsed_metrics
        if m["guest_exit"] != 0:
            failures.append(f"Guest exited with non-zero code {m['guest_exit']}")
        if m["completed"] < 8:
            failures.append(f"Completed buffers ({m['completed']}) < required minimum of 8")
        if m["received"] < 8:
            failures.append(f"Received buffers ({m['received']}) < required minimum of 8")
        if m["canceled"] != 0:
            failures.append(f"Audio buffers canceled: {m['canceled']} (expected 0)")
        if m["errors"] != 0:
            failures.append(f"Audio playback errors reported: {m['errors']} (expected 0)")
        if m["non_silent"] == 0:
            failures.append("All audio buffers were silent (non_silent == 0)")
        if not m["has_positive"]:
            failures.append("No positive PCM samples detected")
        if not m["has_negative"]:
            failures.append("No negative PCM samples detected")
        if m["max_sample"] <= 0:
            failures.append(f"Maximum PCM sample is not strictly positive: {m['max_sample']}")
        if m["min_sample"] >= 0:
            failures.append(f"Minimum PCM sample is not strictly negative: {m['min_sample']}")

    passed = len(failures) == 0

    report = {
        "status": "PASSED" if passed else "FAILED",
        "passed": passed,
        "elapsed_sec": round(elapsed_sec, 4),
        "return_code": return_code,
        "timed_out": timed_out,
        "metrics": parsed_metrics,
        "failures": failures,
        "logs": {
            "stdout": stdout_log_path,
            "stderr": stderr_log_path,
        },
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 50)
    print("      LITEBOX AUDIO PROBE VALIDATION REPORT")
    print("=" * 50)
    print(f"Status:       {report['status']}")
    print(f"Elapsed:      {elapsed_sec:.3f}s")
    print(f"Return Code:  {return_code}")
    if parsed_metrics:
        print(f"Buffers:      recv={m['received']}, sub={m['submitted']}, done={m['completed']}, cancel={m['canceled']}")
        print(f"Audio PCM:    non_silent={m['non_silent']}, min_sample={m['min_sample']}, max_sample={m['max_sample']}")
        print(f"Polarity:     has_pos={m['has_positive']}, has_neg={m['has_negative']}")
        print(f"Guest Exit:   {m['guest_exit']}")
    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"  [X] {f}")
    print("=" * 50 + "\n")

    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description="LiteBox SDL2 audio probe test harness")
    parser.add_argument("--exe", default=DEFAULT_EXE, help="Path to sdl_audio_probe.exe")
    parser.add_argument("--tar", default=DEFAULT_TAR, help="Path to audio-probe.tar")
    parser.add_argument("--timeout", type=float, default=10.0, help="External timeout in seconds")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR, help="Directory to save logs and report")
    parser.add_argument("--build", action="store_true", help="Rebuild probe executable before running")

    args = parser.parse_args()

    if args.build or not os.path.exists(args.exe):
        print("[*] Building sdl_audio_probe example...")
        cmd = ["cargo", "build", "-p", "litebox_runner_linux_on_windows_userland", "--example", "sdl_audio_probe"]
        res = subprocess.run(cmd, cwd=ROOT_DIR)
        if res.returncode != 0:
            print("[!] Failed to build sdl_audio_probe")
            sys.exit(1)

    ret = run_probe(args.exe, args.tar, timeout_sec=args.timeout, log_dir=args.log_dir)
    sys.exit(ret)


if __name__ == "__main__":
    main()
