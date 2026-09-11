"""Measure a Windows host and its descendant processes (development tool).

Usage: python measure.py --pid HOST_PID --seconds 60 --output metrics.json
CPU percentage uses one logical CPU as 100%; it can exceed 100%.
This measures process resources, not frame rate or audible sound.
"""

import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import time


class ProcessEntry(C.Structure):
    _fields_ = [
        ("size", W.DWORD), ("usage", W.DWORD), ("pid", W.DWORD),
        ("heap", C.c_size_t), ("module", W.DWORD), ("threads", W.DWORD),
        ("parent", W.DWORD), ("priority", W.LONG), ("flags", W.DWORD),
        ("name", W.WCHAR * 260),
    ]


class MemoryCounters(C.Structure):
    _fields_ = [
        ("size", W.DWORD), ("page_faults", W.DWORD),
        ("peak_working_set", C.c_size_t), ("working_set", C.c_size_t),
        ("peak_paged_pool", C.c_size_t), ("paged_pool", C.c_size_t),
        ("peak_nonpaged_pool", C.c_size_t), ("nonpaged_pool", C.c_size_t),
        ("pagefile", C.c_size_t), ("peak_pagefile", C.c_size_t),
        ("private_bytes", C.c_size_t),
    ]


def configure():
    kernel = C.WinDLL("kernel32", use_last_error=True)
    psapi = C.WinDLL("psapi", use_last_error=True)
    signatures = [
        (kernel.CreateToolhelp32Snapshot, [W.DWORD, W.DWORD], W.HANDLE),
        (kernel.Process32FirstW, [W.HANDLE, C.POINTER(ProcessEntry)], W.BOOL),
        (kernel.Process32NextW, [W.HANDLE, C.POINTER(ProcessEntry)], W.BOOL),
        (kernel.OpenProcess, [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
        (kernel.CloseHandle, [W.HANDLE], W.BOOL),
        (kernel.GetProcessTimes, [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4, W.BOOL),
        (psapi.GetProcessMemoryInfo,
         [W.HANDLE, C.POINTER(MemoryCounters), W.DWORD], W.BOOL),
    ]
    for func, args, result in signatures:
        func.argtypes, func.restype = args, result
    return kernel, psapi


def process_tree(kernel, root_pid):
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if snapshot == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    entries = {}
    try:
        entry = ProcessEntry()
        entry.size = C.sizeof(entry)
        more = kernel.Process32FirstW(snapshot, C.byref(entry))
        while more:
            entries[entry.pid] = (entry.parent, entry.name)
            more = kernel.Process32NextW(snapshot, C.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    selected = {root_pid} if root_pid in entries else set()
    while True:
        expanded = selected | {pid for pid, (parent, _) in entries.items()
                               if parent in selected}
        if expanded == selected:
            return {pid: entries[pid][1] for pid in selected}
        selected = expanded


def ticks(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


def sample_process(kernel, psapi, pid, name):
    handle = kernel.OpenProcess(0x400 | 0x10, False, pid)
    if not handle:
        raise C.WinError(C.get_last_error())
    try:
        created, exited, system, user = (W.FILETIME() for _ in range(4))
        if not kernel.GetProcessTimes(handle, C.byref(created), C.byref(exited),
                                      C.byref(system), C.byref(user)):
            raise C.WinError(C.get_last_error())
        memory = MemoryCounters()
        memory.size = C.sizeof(memory)
        if not psapi.GetProcessMemoryInfo(handle, C.byref(memory), memory.size):
            raise C.WinError(C.get_last_error())
        return {"pid": pid, "name": name, "created_ticks": ticks(created),
                "cpu_seconds": (ticks(system) + ticks(user)) / 10_000_000,
                "working_set_bytes": memory.working_set,
                "private_bytes": memory.private_bytes}
    finally:
        kernel.CloseHandle(handle)


def measure(pid, seconds, interval):
    kernel, psapi = configure()
    start = time.monotonic()
    samples, errors, baselines, latest = [], [], {}, {}
    while True:
        now = time.monotonic() - start
        tree = process_tree(kernel, pid)
        if not tree:
            if not samples:
                raise ValueError(f"Process {pid} does not exist")
            break
        processes = []
        for child_pid, name in tree.items():
            try:
                p = sample_process(kernel, psapi, child_pid, name)
            except OSError as exc:
                errors.append({"elapsed": now, "pid": child_pid, "error": str(exc)})
                continue
            key = (p["pid"], p["created_ticks"])
            # A creation time makes PID reuse a different process identity.
            baselines.setdefault(key, p["cpu_seconds"])
            latest[key] = p["cpu_seconds"]
            processes.append(p)
        samples.append({"elapsed_seconds": now, "processes": processes})
        if now >= seconds:
            break
        time.sleep(min(interval, seconds - now))
    elapsed = time.monotonic() - start
    cpu = sum(value - baselines[key] for key, value in latest.items())
    return {
        "root_pid": pid, "elapsed_seconds": elapsed,
        "logical_cpu_count": os.cpu_count(), "cpu_seconds_observed": cpu,
        "cpu_percent_one_core": 100 * cpu / elapsed,
        "peak_tree_working_set_bytes": max(
            sum(p["working_set_bytes"] for p in s["processes"]) for s in samples),
        "peak_tree_private_bytes": max(
            sum(p["private_bytes"] for p in s["processes"]) for s in samples),
        "limitations": [
            "CPU deltas begin at each process's first successful sample.",
            "Short-lived descendants and CPU after their final sample can be missed.",
            "Summed working sets can double-count shared pages.",
            "No FPS, input latency or audio quality is inferred from these counters.",
        ],
        "errors": errors, "samples": samples,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required")
    if args.pid <= 0 or args.seconds <= 0 or args.interval <= 0:
        parser.error("pid, seconds and interval must be positive")
    result = measure(args.pid, args.seconds, args.interval)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "samples"}, indent=2))


if __name__ == "__main__":
    main()
