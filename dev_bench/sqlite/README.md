# SQLite Benchmark (speedtest1)

Run SQLite's official [speedtest1](https://www.sqlite.org/src/file/test/speedtest1.c) benchmark natively and under LiteBox, then compare results.

**Why:** Single-process, no networking needed, filesystem ops go to ramfs. Extremely common benchmark in OS/sandbox papers. Exercises mmap, file I/O, and compute together.

**How:** `speedtest1` is statically compiled from the SQLite amalgamation — no runtime dependencies needed. Runs on `:memory:` by default (or a file-backed database with `--no-memory`).

## Prerequisites

- `gcc`, `make` on the host (to build SQLite + speedtest1).
- Pre-built LiteBox binaries (auto-built by the script unless `--no-build` is passed).

Build LiteBox (from workspace root):
```bash
cargo build --release -p litebox_runner_linux_userland -p litebox_packager
```

The SQLite source (v3.51.3) is downloaded automatically on first run.

## Quick Start

```bash
# Run both native and LiteBox (default: :memory:, size=100, 3 iterations)
python3 dev_bench/sqlite/run_sqlite.py --release

# Run only native
python3 dev_bench/sqlite/run_sqlite.py --mode native

# Run only LiteBox
python3 dev_bench/sqlite/run_sqlite.py --mode litebox --release

# More iterations for stable results
python3 dev_bench/sqlite/run_sqlite.py --iterations 5 --release

# Larger workload
python3 dev_bench/sqlite/run_sqlite.py --size 200 --release

# File-backed database instead of :memory:
python3 dev_bench/sqlite/run_sqlite.py --no-memory --release

# Save results to JSON
python3 dev_bench/sqlite/run_sqlite.py --release --output results.json
```

## What It Runs

The script:

1. Downloads SQLite source (v3.51.3) if not already present.
2. Generates the amalgamation (`sqlite3.c`) via `configure && make sqlite3.c`.
3. Statically compiles `speedtest1` from `sqlite3.c` + `test/speedtest1.c`.
4. Runs `speedtest1 --size <N> --memdb` natively and/or under LiteBox (default testset: `mix1` = main, orm, cte, json, fp, parsenumber, rtree, star, app).
5. Parses the `TOTAL` time from speedtest1 output.
6. Prints a comparison table.

## Output Format

```
================================================================================
Benchmark                   Native (s)  LiteBox (s)    Ratio   Overhead
--------------------------------------------------------------------------------
sqlite-speedtest1(:memory:)        3.763        3.664   0.9738     -2.62%
================================================================================

Geometric mean time ratio (LiteBox/Native): 0.9738
Overhead: -2.62%
```

- **Ratio** = LiteBox time / Native time. Values near 1.0 mean no overhead.
- **Overhead** = percentage slowdown. Positive means LiteBox is slower.

## Options

| Flag | Default | Description |
|---|---|---|
| `--mode {both,native,litebox}` | `both` | Which runs to perform |
| `--size N` | `100` | Size multiplier for speedtest1 workload |
| `--no-memory` | (off) | Use file-backed DB instead of `:memory:` |
| `--iterations N` | `3` | Number of iterations per mode |
| `--release` | (off) | Use release build of LiteBox binaries |
| `--runner-path PATH` | (auto) | Path to `litebox_runner_linux_userland` |
| `--packager-path PATH` | (auto) | Path to `litebox_packager` |
| `--no-build` | (off) | Skip building LiteBox binaries |
| `--output FILE` | (none) | Save results to JSON |
| `--work-dir DIR` | (temp) | Working directory for intermediate files |
