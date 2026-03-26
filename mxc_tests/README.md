# MXC Python Harness

This folder contains a small Windows-hosted harness for running the
Python-based configs from `microsoft/mxc/test_configs` against
`litebox_runner_linux_on_windows_userland`.

The harness:

- starts `litebox_broker.exe` automatically for each config
- uses a temporary Windows AF_UNIX socket path for local broker IPC by default
- passes the same endpoint as both `--network-broker` and `--nine-p-broker`
- exposes the host through broker-backed 9P with `--read-only` plus per-config
  `--writable-path` exceptions derived from MXC's `filesystem.readwritePaths`
- rewrites Windows-style filesystem paths in the Python snippets so they hit the
  broker-backed lower layer instead of falling into the in-memory upper layer
- writes a JSON results file plus a broker log
- prints each test result as soon as that config finishes, followed by a final
  summary

Configs whose `script` field is not a `python -c "..."` one-liner are reported
as `skipped`.

## Prerequisites

Before running the harness, make sure you have:

1. This LiteBox repo checked out on a Windows x86_64 machine.
2. The `microsoft/mxc` repo cloned somewhere on the same machine.
3. A Rust toolchain with `cargo` available on the Windows host.
4. Python 3 available on the Windows host so you can run the harness itself.
5. Network access for `litebox_packager --oci-image`.

You also need the LiteBox broker and Linux-on-Windows runner built in release
mode:

```powershell
cargo build -p litebox_broker -p litebox_runner_linux_on_windows_userland --release
```

The harness defaults to the release binaries under this repo's `target\release`
directory, resolved from the script location rather than the current working
directory:

- `target\release\litebox_broker.exe`
- `target\release\litebox_runner_linux_on_windows_userland.exe`

## Create the Python tar with `litebox_packager`

The harness expects a Linux rootfs tar that already contains a Python runtime.
The simplest path is to package an OCI image with `litebox_packager`.

Create an output directory first:

```powershell
New-Item -ItemType Directory -Force C:\temp\litebox-python | Out-Null
```

Then build the tar from the public Python image:

```powershell
cargo run -p litebox_packager --release -- --oci-image docker.io/library/python:3.12-slim -o C:\temp\litebox-python\python-3.12-slim-rewritten.tar
```

What this does:

- pulls `docker.io/library/python:3.12-slim`
- extracts the image root filesystem
- rewrites executable Linux ELFs for LiteBox execution
- writes a tar file that can be passed to the runner with `--initial-files`

Notes:

- `--oci-image` packaging is supported on x86_64.
- The tar name is up to you. The harness examples below use
  `python-3.12-slim-rewritten.tar` because it is descriptive, not because the
  filename itself is required.
- If your Python workload needs extra files baked into the tar, use the normal
  `litebox_packager` flags such as `--include` or `--rewrite-include`.

## Run the harness

Point the harness at:

- the MXC config directory
- the Python tar you created above

Example:

```powershell
python mxc_tests\run_mxc_configs.py `
  --config-dir C:\Users\wdcui\mxc\test_configs `
  --python-tar C:\temp\litebox-python\python-3.12-slim-rewritten.tar
```

By default, the harness:

- starts its own broker for each config
- uses an AF_UNIX socket path under `%TEMP%\litebox-mxc\` for both network IPC
  and direct 9P IPC
- points the broker's 9P root at `C:\`
- applies `--read-only` plus per-config `--writable-path` entries from the MXC
  `filesystem` block
- rewrites Windows filesystem paths in the script to guest 9P paths (for
  example, `C:\temp\foo\bar.txt` becomes `/temp/foo/bar.txt`)
- uses the repo's release broker/runner binaries
- writes results under `%TEMP%\litebox-mxc\`

If you want to override the IPC endpoint explicitly:

```powershell
python mxc_tests\run_mxc_configs.py `
  --config-dir C:\Users\wdcui\mxc\test_configs `
  --python-tar C:\temp\litebox-python\python-3.12-slim-rewritten.tar `
  --broker-endpoint C:\temp\litebox-mxc\custom-broker.sock
```

You can also override the binary, broker root, and log locations when needed:

```powershell
python mxc_tests\run_mxc_configs.py `
  --config-dir C:\Users\wdcui\mxc\test_configs `
  --python-tar C:\temp\litebox-python\python-3.12-slim-rewritten.tar `
  --broker C:\path\to\litebox_broker.exe `
  --runner C:\path\to\litebox_runner_linux_on_windows_userland.exe `
  --broker-root C:\ `
  --results-path C:\temp\mxc-results.json `
  --broker-log C:\temp\mxc-broker.log
```

## How to interpret the output

For each config, the harness prints one line like:

```text
[ok] basic_appcontainer.json rc=0
```

The status values mean:

- `ok`: LiteBox returned exit code `0` for that config.
- `failed`: LiteBox returned a non-zero exit code or the config timed out.
- `skipped`: the config was not a `python -c "..."` case, so this harness did
  not try to run it.

The summary line at the end looks like this:

```text
Summary: ok=<N> failed=<N> skipped=<N> semantic_warnings=<N>
```

Interpret it as follows:

- `ok`, `failed`, and `skipped` are the harness-level execution counts.
- `semantic_warnings` counts runs that exited successfully but whose stdout
  still contained `ERROR:` or `Error:`. Those cases deserve manual review even
  though the process exit code was `0`.
- After the 9P-over-IPC change, the file-based BFS warnings should be gone when
  the broker-backed lower layer is active; remaining semantic warnings are
  expected to be policy mismatches in other areas (for example, network rules).

The JSON results file contains full per-config detail:

- `name`: config filename
- `status`: `ok`, `failed`, or `skipped`
- `reason`: extra failure/skip text such as a timeout reason
- `notes`: harness-side adjustments that were applied before running
- `returncode`: guest process exit code when one exists
- `stdout`: captured guest stdout
- `stderr`: captured guest stderr
- `semantic_warning`: boolean flag derived from stdout contents

## Harness-specific notes

The harness applies a few compatibility tweaks that were useful during earlier
MXC sweeps:

- prepends `import sys` if a config uses `sys.` without importing it
- seeds the readonly BFS input file on the host before running
  `filesystem_bfs_readonly_test.json`
- injects a lightweight `colorama` fallback stub when a config imports
  `Fore` and `Style`
- translates Windows-style paths in the Python source to guest paths backed by
  the broker-mounted 9P lower layer

Those adjustments are reported in the `notes` field for each affected result.
