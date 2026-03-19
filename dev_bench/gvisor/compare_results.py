#!/usr/bin/env python3
"""Compare gVisor microbenchmark results across native, litebox, and gvisor modes.

Parses the latest summary file from each subdirectory under benchmark_results/
and prints a table of ratios relative to native.

Usage:
    python3 compare_results.py [benchmark_results_dir]
"""

import os
import re
import sys
from pathlib import Path

# Benchmarks we care about: (display_name, regex pattern for the median line)
BENCHMARKS = [
    ("getpid",                  r"^BM_Getpid_median\s"),
    ("getpid (opt)",            r"^BM_GetpidOpt_median\s"),
    ("gettid (1 thread)",       r"^BM_Gettid/real_time/threads:1_median\s"),
    ("clock_gettime (MONO)",    r"^BM_VDSOClockGettime/1_median\s"),
    ("clock_getres",            r"^BM_ClockGetRes_median\s"),
    ("futex wake (nop)",        r"^BM_FutexWakeNop.+_median\s"),
    ("futex wait (nop)",        r"^BM_FutexWaitNop.+_median\s"),
    ("epoll (timeout=0)",       r"^BM_EpollTimeout/0_median\s"),
    ("poll (timeout=0)",        r"^BM_PollTimeout/0_median\s"),
    ("select (timeout=0)",      r"^BM_SelectTimeout/0_median\s"),
    ("open (1)",                r"^BM_Open/1/real_time_median\s"),
    ("read (1B)",               r"^BM_Read/1/real_time_median\s"),
    ("write (1B)",              r"^BM_Write/1/real_time_median\s"),
    ("open_read_close (1KB)",   r"^BM_OpenReadClose/1000/real_time_median\s"),
    ("stat (1)",                r"^BM_Stat/1/real_time_median\s"),
    ("unlink (1)",              r"^BM_Unlink/1/real_time_median\s"),
    ("randread (1B)",           r"^BM_RandRead/1/real_time_median\s"),
    ("seqwrite (1B)",           r"^BM_SeqWrite/1/real_time_median\s"),
    ("mmap/munmap (1 page)",    r"^BM_MapUnmap/1/real_time_median\s"),
    ("signal (fault+fixup)",    r"^BM_FaultSignalFixup/real_time_median\s"),
    ("pipe (1B)",               r"^BM_Pipe/1/real_time_median\s"),
    ("sendmsg (UDS 1KB)",       r"^BM_Sendmsg/real_time_median\s"),
    ("recvmsg (UDS 1KB)",       r"^BM_Recvmsg/real_time_median\s"),
    ("dup (1)",                 r"^BM_Dup/1/real_time_median\s"),
    ("sleep (0)",               r"^BM_Sleep/0/real_time_median\s"),
    ("thread start (1)",        r"^BM_ThreadStart/1/real_time_median\s"),
    ("process lifecycle (1)",    r"^BM_ProcessLifecycle/1/real_time_median\s"),
    ("getdents (1 file)",       r"^BM_GetdentsNewFD/1/real_time_median\s"),
]


def find_latest_file(directory: Path) -> Path | None:
    """Return the most recently modified summary file in a directory."""
    files = sorted(directory.glob("summary_*.txt"))
    return files[-1] if files else None


def parse_median_ns(line: str) -> float | None:
    """Extract the first time value (in ns) from a benchmark median line.

    Handles units: ns, us, ms, s.
    """
    # Match patterns like "162 ns", "1.23 us", "21.1 ns"
    m = re.search(r"(\d+(?:\.\d+)?)\s*(ns|us|ms|s)\b", line)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2)
    multipliers = {"ns": 1.0, "us": 1e3, "ms": 1e6, "s": 1e9}
    return value * multipliers[unit]


def parse_results(filepath: Path) -> dict[str, float]:
    """Parse a summary file and return {benchmark_name: median_ns}."""
    text = filepath.read_text()
    results = {}
    for name, pattern in BENCHMARKS:
        for line in text.splitlines():
            if re.match(pattern, line.strip()):
                ns = parse_median_ns(line)
                if ns is not None:
                    results[name] = ns
                break
    return results


def main():
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "benchmark_results"

    modes = {}
    for mode in ["native", "litebox", "gvisor"]:
        mode_dir = base / mode
        if not mode_dir.is_dir():
            continue
        f = find_latest_file(mode_dir)
        if f:
            modes[mode] = parse_results(f)
            print(f"# Loaded {mode}: {f.name}", file=sys.stderr)

    if "native" not in modes:
        print("ERROR: no native results found", file=sys.stderr)
        sys.exit(1)

    native = modes["native"]
    others = {k: v for k, v in modes.items() if k != "native"}

    # Header
    cols = ["Benchmark", "Native (ns)"] + [f"{m} (ns)" for m in others] + [f"{m}/native" for m in others]
    widths = [28, 12] + [12] * len(others) + [12] * len(others)
    header = "  ".join(c.rjust(w) for c, w in zip(cols, widths))
    print(header)
    print("-" * len(header))

    for name, _ in BENCHMARKS:
        nat_ns = native.get(name)
        if nat_ns is None:
            continue
        parts = [name.ljust(28), f"{nat_ns:12.0f}"]
        for m in others:
            val = others[m].get(name)
            parts.append(f"{val:12.0f}" if val is not None else f"{'N/A':>12}")
        for m in others:
            val = others[m].get(name)
            if val is not None and nat_ns > 0:
                ratio = val / nat_ns
                parts.append(f"{ratio:12.2f}")
            else:
                parts.append(f"{'N/A':>12}")
        print("  ".join(parts))


if __name__ == "__main__":
    main()
