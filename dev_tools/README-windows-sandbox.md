# Running Copilot in the Windows Sandbox

This guide covers running GitHub Copilot CLI inside the litebox Windows
userland sandbox from scratch.

## Prerequisites

- **Rust toolchain** — install via [rustup](https://rustup.rs/)
- **GitHub CLI** — `gh` must be installed and authenticated (`gh auth login`)
- **GitHub Copilot CLI** — install via `winget install GitHub.Copilot`
- **Python 3** — needed to run the DLL tar builder script

## Step 1: Build the binaries

```powershell
cargo build --release -p litebox_runner_windows_userland -p litebox_broker
```

## Step 2: Build the DLL tar

The sandbox intercepts all guest syscalls and provides its own virtual
filesystem. The guest binary never touches real host DLLs — instead, we
pre-package the required Windows system DLLs into a tar archive that the
runner loads into its VFS:

```powershell
python dev_tools\build_windows_dlls_tar.py -o C:\Users\wdcui\tmp\node_windows.tar
```

This packs ntdll.dll, kernel32.dll, ucrt, and other system DLLs that
Node.js-based binaries (including Copilot) need. The `--exe` flag can
optionally include a guest executable in the tar, but for Copilot we pass
it separately via `--pe-file`.

## Step 3: Start the broker

The broker is a single process that provides both network proxying and 9P
host filesystem access over an AF_UNIX socket:

```powershell
# Create the 9P root directory (files here are visible inside the sandbox)
mkdir C:\Users\wdcui\tmp\9p_root -Force

# Delete stale socket from a previous run
Remove-Item C:\Users\wdcui\tmp\litebox.sock -ErrorAction SilentlyContinue

# Start the broker in the background
Start-Process -FilePath "target\release\litebox_broker.exe" `
    -ArgumentList '--network-proxy-listen', 'C:\Users\wdcui\tmp\litebox.sock', `
                  '--root-dir', 'C:\Users\wdcui\tmp\9p_root' `
    -PassThru -WindowStyle Hidden
```

**The socket file must be deleted between broker restarts** — the broker
refuses to bind if it already exists.

## Step 4: Run Copilot

```powershell
$token = gh auth token
& "target\release\litebox_runner_windows_userland.exe" `
    --dll-tar "C:\Users\wdcui\tmp\node_windows.tar" `
    --pe-file "C:\Users\wdcui\AppData\Local\Microsoft\WinGet\Packages\GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe\copilot.exe" `
    --network-broker "C:\Users\wdcui\tmp\litebox.sock" `
    --nine-p-broker "C:\Users\wdcui\tmp\litebox.sock" `
    --env "GH_TOKEN=$token" `
    -- -p "say hello"
```

- `--dll-tar` — the system DLLs tar from step 2
- `--pe-file` — the guest executable (copilot.exe, node.exe, python.exe, etc.)
- `--network-broker` / `--nine-p-broker` — both point to the same broker socket
- `--env` — injects environment variables into the sandbox
- Everything after `--` is passed to the guest binary

Drop `-- -p "say hello"` for an interactive Copilot session.

## Automated script

`run_copilot_windows_sandbox.ps1` handles broker lifecycle and token
retrieval automatically:

```powershell
.\dev_tools\run_copilot_windows_sandbox.ps1 -p "say hello"
```

## Running Node.js or Python directly

These don't need the broker (no networking or 9P):

```powershell
# Node.js
& "target\release\litebox_runner_windows_userland.exe" `
    --dll-tar "C:\Users\wdcui\tmp\node_windows.tar" `
    --pe-file "C:\Program Files\nodejs\node.exe" `
    -- -e "console.log('hello from sandbox')"

# Python
& "target\release\litebox_runner_windows_userland.exe" `
    --dll-tar "C:\Users\wdcui\tmp\python_t32_with_stdlib.tar" `
    --pe-file "C:\Users\wdcui\AppData\Local\Python\pythoncore-3.14-64\python.exe" `
    -- -c "print('hello from sandbox')"
```

## Restarting the broker

```powershell
Stop-Process -Name litebox_broker -Force
Remove-Item C:\Users\wdcui\tmp\litebox.sock -ErrorAction SilentlyContinue
# Then run the Start-Process command from Step 3 again
```

## Troubleshooting

- **Broker won't start** — Delete `C:\Users\wdcui\tmp\litebox.sock` and retry.
- **DNS failures** — The runner auto-injects a JS patch that forces c-ares DNS
  resolution. This is transparent and should just work.
- **Timeout on LLM streaming** — The watchdog is 120s to accommodate slow
  model responses.
- **Debug build** — `cargo build --release -p litebox_runner_windows_userland --features trace_debug`
