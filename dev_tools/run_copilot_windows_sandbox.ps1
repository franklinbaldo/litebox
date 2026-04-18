# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

<#
.SYNOPSIS
    Launch GitHub Copilot CLI inside the litebox Windows userland sandbox.

.DESCRIPTION
    Starts the broker (if not already running), obtains a GH token, and runs
    Copilot inside the sandbox with networking and 9P filesystem support.

    Prerequisites:
      1. Build:  cargo build --release -p litebox_runner_windows_userland -p litebox_broker
      2. Prepare DLL tar:  python dev_tools\build_windows_dlls_tar.py --exe "<node path>" --output <tar path>
      3. gh auth login

    See dev_tools\README-windows-sandbox.md for full setup instructions.

.PARAMETER CopilotArgs
    Additional arguments passed to copilot (e.g., -p "say hello").

.EXAMPLE
    .\dev_tools\run_copilot_windows_sandbox.ps1                    # interactive
    .\dev_tools\run_copilot_windows_sandbox.ps1 -p "say hello"    # one-shot
#>

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$CopilotArgs
)

$ErrorActionPreference = 'Stop'

# --- Paths -------------------------------------------------------------------
$RepoRoot   = (Resolve-Path "$PSScriptRoot\..").Path
$Runner     = Join-Path $RepoRoot 'target\release\litebox_runner_windows_userland.exe'
$Broker     = Join-Path $RepoRoot 'target\release\litebox_broker.exe'
$DllTar     = if ($env:DLL_TAR)      { $env:DLL_TAR }      else { 'C:\Users\wdcui\tmp\node_windows.tar' }
$BrokerSock = if ($env:BROKER_SOCK)  { $env:BROKER_SOCK }  else { 'C:\Users\wdcui\tmp\litebox.sock' }
$NinePRoot  = if ($env:NINEP_ROOT)   { $env:NINEP_ROOT }   else { 'C:\Users\wdcui\tmp\9p_root' }

# Find copilot binary.
$CopilotBin = (Get-Command copilot -ErrorAction SilentlyContinue).Source
if (-not $CopilotBin) {
    Write-Error "copilot not found on PATH. Install with: winget install GitHub.Copilot"
    exit 1
}

# Verify runner exists.
if (-not (Test-Path $Runner)) {
    Write-Error "Runner not found at $Runner`nRun: cargo build --release -p litebox_runner_windows_userland"
    exit 1
}

# Verify DLL tar exists.
if (-not (Test-Path $DllTar)) {
    Write-Error "DLL tar not found at $DllTar`nRun: python dev_tools\build_windows_dlls_tar.py --exe `"C:\Program Files\nodejs\node.exe`" --output $DllTar"
    exit 1
}

# --- Start broker if needed --------------------------------------------------
$StartedBroker = $false
$BrokerProcess = $null

function Start-Broker {
    if (-not (Test-Path $Broker)) {
        Write-Error "Broker not found at $Broker`nRun: cargo build --release -p litebox_broker"
        exit 1
    }

    # Ensure 9P root exists.
    if (-not (Test-Path $NinePRoot)) {
        New-Item -ItemType Directory -Path $NinePRoot -Force | Out-Null
    }

    # Remove stale socket.
    Remove-Item $BrokerSock -ErrorAction SilentlyContinue

    $script:BrokerProcess = Start-Process -FilePath $Broker `
        -ArgumentList '--network-proxy-listen', $BrokerSock, '--root-dir', $NinePRoot `
        -PassThru -WindowStyle Hidden
    $script:StartedBroker = $true

    # Wait for socket to appear.
    for ($i = 0; $i -lt 50; $i++) {
        if (Test-Path $BrokerSock) { return }
        Start-Sleep -Milliseconds 100
    }
    Write-Error "Broker did not create socket at $BrokerSock"
    exit 1
}

# Check if broker is already running.
$existingBroker = Get-Process -Name litebox_broker -ErrorAction SilentlyContinue
if ($existingBroker -and (Test-Path $BrokerSock)) {
    Write-Host "Using existing broker (PID $($existingBroker.Id))"
} else {
    Write-Host "Starting broker..."
    Start-Broker
}

# --- Obtain GH token ---------------------------------------------------------
$token = & gh auth token
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to get GH token. Run: gh auth login"
    exit 1
}

# --- Run copilot in sandbox --------------------------------------------------
$RunnerArgs = @(
    '--dll-tar',        $DllTar
    '--pe-file',        $CopilotBin
    '--network-broker', $BrokerSock
    '--nine-p-broker',  $BrokerSock
    '--env',            "GH_TOKEN=$token"
    '--'
)

if ($CopilotArgs) {
    $RunnerArgs += $CopilotArgs
}

try {
    & $Runner @RunnerArgs
} finally {
    # Clean up broker if we started it.
    if ($StartedBroker -and $BrokerProcess -and -not $BrokerProcess.HasExited) {
        Stop-Process -Id $BrokerProcess.Id -Force -ErrorAction SilentlyContinue
        Remove-Item $BrokerSock -ErrorAction SilentlyContinue
    }
}
