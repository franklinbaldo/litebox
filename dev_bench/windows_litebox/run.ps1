[CmdletBinding()]
param(
    [ValidateRange(1, 100)] [int]$Samples = 15,
    [ValidateRange(0, 20)] [int]$Warmups = 3,
    [string[]]$Cases = @('startup', 'cpu', 'memory', 'filesystem', 'syscall', 'clock', 'threads', 'fsync', 'unlink_open'),
    [ValidateRange(1, 4096)] [int]$Units = 32,
    [string]$LiteBox,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here '..\..')).Path
$artifacts = Join-Path $here 'artifacts'
$manifest = Join-Path $here 'Cargo.toml'
$windowsTarget = 'x86_64-pc-windows-gnullvm'
$linuxTarget = 'x86_64-unknown-linux-musl'
$rustToolchain = 'stable-x86_64-pc-windows-gnullvm'
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = 'rust-lld'
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS = '-C target-feature=+crt-static'
$nativeProgram = Join-Path $here "target\$windowsTarget\release\litebox-perf-workload.exe"
$linuxProgram = Join-Path $here "target\$linuxTarget\release\litebox-perf-workload"
$rootfs = Join-Path $artifacts 'rootfs'
$rewrittenProgram = Join-Path $rootfs 'usr\local\bin\litebox-perf-workload'
$image = Join-Path $artifacts 'perf-rootfs.tar'
$rawResult = Join-Path $artifacts 'results.json'
$markdownResult = Join-Path $artifacts 'report.md'

if (-not $LiteBox) {
    $candidate = Join-Path $repo 'target\release\litebox.exe'
    $LiteBox = if (Test-Path $candidate) { $candidate } else { 'litebox' }
}

function Invoke-Checked([scriptblock]$Command, [string]$Description) {
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Description failed with exit code $LASTEXITCODE" }
}

function Get-Percentile([double[]]$Values, [double]$Percentile) {
    $sorted = @($Values | Sort-Object)
    $index = [Math]::Max(0, [Math]::Ceiling($Percentile * $sorted.Count) - 1)
    $sorted[$index]
}

function Measure-Workload([string]$Mode, [string]$Case, [int]$Sequence) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Mode -eq 'windows') {
            $output = & $nativeProgram $Case $Units 2>&1 | Out-String
        } else {
            $output = & $LiteBox run --env HOME=/tmp --env TMPDIR=/tmp $image /usr/local/bin/litebox-perf-workload $Case $Units 2>&1 | Out-String
        }
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    $watch.Stop()
    $jsonLine = @($output -split "`r?`n" | Where-Object { $_.TrimStart().StartsWith('{') })[-1]
    if ($exitCode -ne 0 -or -not $jsonLine) {
        return [pscustomobject]@{
            mode = $Mode; case = $Case; sequence = $Sequence; units = $Units; status = 'unsupported_or_failed'
            wall_ns = [int64]($watch.Elapsed.TotalMilliseconds * 1000000); workload_ns = $null
            harness_overhead_ns = $null; checksum = $null; error = $output.Trim()
        }
    }
    $internal = $jsonLine | ConvertFrom-Json
    $wallNs = [int64]($watch.Elapsed.TotalMilliseconds * 1000000)
    [pscustomobject]@{
        mode = $Mode; case = $Case; sequence = $Sequence; units = $Units; status = 'ok'
        wall_ns = $wallNs; workload_ns = [int64]$internal.elapsed_ns
        harness_overhead_ns = [Math]::Max(0, $wallNs - [int64]$internal.elapsed_ns)
        checksum = [uint64]$internal.checksum; error = $null
    }
}

if (-not $SkipBuild) {
    if (@(rustup target list --installed --toolchain $rustToolchain) -notcontains $linuxTarget) {
        throw "Missing $linuxTarget. Run: rustup target add $linuxTarget --toolchain $rustToolchain"
    }
    Invoke-Checked { cargo "+$rustToolchain" build --manifest-path $manifest --release --target $windowsTarget } 'Windows workload build'
    Invoke-Checked { cargo "+$rustToolchain" build --manifest-path $manifest --release --target $linuxTarget } 'Linux workload build'
}
foreach ($required in @($nativeProgram, $linuxProgram)) {
    if (-not (Test-Path $required)) { throw "Required binary not found: $required" }
}

New-Item -ItemType Directory -Force $artifacts, (Join-Path $rootfs 'usr\local\bin'), (Join-Path $rootfs 'tmp') | Out-Null
Invoke-Checked { & $LiteBox rewrite $linuxProgram --output $rewrittenProgram } 'LiteBox syscall rewrite'
if (Test-Path $image) { Remove-Item -LiteralPath $image }
Invoke-Checked { tar.exe -cf $image -C $rootfs . } 'root filesystem archive creation'

Write-Host "Warming up ($Warmups paired runs per case)..."
foreach ($case in $Cases) {
    for ($index = 0; $index -lt $Warmups; $index++) {
        $null = Measure-Workload windows $case $index
        $null = Measure-Workload litebox $case $index
    }
}

Write-Host "Measuring ($Samples paired runs per case)..."
$measurements = @()
foreach ($case in $Cases) {
    for ($index = 0; $index -lt $Samples; $index++) {
        $order = if ($index % 2 -eq 0) { @('windows', 'litebox') } else { @('litebox', 'windows') }
        foreach ($mode in $order) {
            $measurement = Measure-Workload $mode $case $index
            $measurements += $measurement
            if ($measurement.status -eq 'ok') {
                Write-Host ("  {0,-10} {1,-10} {2,9:N2} ms" -f $case, $mode, ($measurement.wall_ns / 1000000))
            } else {
                Write-Host ("  {0,-10} {1,-10} UNSUPPORTED/FAILED" -f $case, $mode)
            }
        }
    }
}

$summary = foreach ($case in $Cases) {
    $winRows = @($measurements | Where-Object { $_.case -eq $case -and $_.mode -eq 'windows' -and $_.status -eq 'ok' })
    $boxRows = @($measurements | Where-Object { $_.case -eq $case -and $_.mode -eq 'litebox' -and $_.status -eq 'ok' })
    if ($winRows.Count -eq 0 -or $boxRows.Count -eq 0) {
        [pscustomobject]@{ case = $case; status = 'compatibility_difference'; windows_status = $(if ($winRows.Count) { 'ok' } else { 'unsupported_or_failed' }); litebox_status = $(if ($boxRows.Count) { 'ok' } else { 'unsupported_or_failed' }); windows_median_ms = $null; litebox_median_ms = $null; slowdown = $null; windows_p95_ms = $null; litebox_p95_ms = $null; windows_overhead_median_ms = $null; litebox_overhead_median_ms = $null }
        continue
    }
    $win = [double[]]@($winRows | ForEach-Object wall_ns)
    $box = [double[]]@($boxRows | ForEach-Object wall_ns)
    $winMedian = Get-Percentile $win 0.50
    $boxMedian = Get-Percentile $box 0.50
    [pscustomobject]@{
        case = $case; status = 'ok'; windows_status = 'ok'; litebox_status = 'ok'
        windows_median_ms = $winMedian / 1e6
        litebox_median_ms = $boxMedian / 1e6
        slowdown = $boxMedian / $winMedian
        windows_p95_ms = (Get-Percentile $win 0.95) / 1e6
        litebox_p95_ms = (Get-Percentile $box 0.95) / 1e6
        windows_overhead_median_ms = (Get-Percentile ([double[]]@($winRows | ForEach-Object harness_overhead_ns)) 0.50) / 1e6
        litebox_overhead_median_ms = (Get-Percentile ([double[]]@($boxRows | ForEach-Object harness_overhead_ns)) 0.50) / 1e6
    }
}

$cpu = try { (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim() } catch { $env:PROCESSOR_IDENTIFIER }
$metadata = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString('o'); os = [Environment]::OSVersion.VersionString
    cpu = $cpu; logical_processors = [Environment]::ProcessorCount; rustc = (rustc "+$rustToolchain" --version)
    litebox = (& $LiteBox version 2>&1 | Out-String).Trim(); samples = $Samples; warmups = $Warmups; units = $Units
    windows_binary_sha256 = (Get-FileHash -Algorithm SHA256 $nativeProgram).Hash.ToLowerInvariant()
    linux_binary_sha256 = (Get-FileHash -Algorithm SHA256 $linuxProgram).Hash.ToLowerInvariant()
    rootfs_sha256 = (Get-FileHash -Algorithm SHA256 $image).Hash.ToLowerInvariant()
}
[ordered]@{ metadata = $metadata; summary = $summary; measurements = $measurements } | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 $rawResult

$lines = @('# Windows vs LiteBox performance', '', "Generated: $($metadata.generated_at)", '',
    '| Workload | Windows median | LiteBox median | Slowdown | Windows overhead | LiteBox overhead |',
    '|---|---:|---:|---:|---:|---:|')
foreach ($row in $summary) {
    if ($row.status -eq 'ok') {
        $lines += "| $($row.case) | $($row.windows_median_ms.ToString('N2')) ms | $($row.litebox_median_ms.ToString('N2')) ms | $($row.slowdown.ToString('N2'))x | $($row.windows_overhead_median_ms.ToString('N2')) ms | $($row.litebox_overhead_median_ms.ToString('N2')) ms |"
    } else {
        $lines += "| $($row.case) | $($row.windows_status) | $($row.litebox_status) | compatibility difference | n/a | n/a |"
    }
}
$lines += @('', 'Overhead is wall-clock minus time measured inside the workload; it includes PowerShell/process plumbing and, for LiteBox, TAR loading and sandbox startup.',
    'Paired execution order alternates. Network and unsupported-operation probes are documented but excluded from the performance score.', '', 'Raw measurements: `results.json`')
$lines | Set-Content -Encoding utf8 $markdownResult
$summary | Format-Table -AutoSize
Write-Host "Raw results: $rawResult"
Write-Host "Report:      $markdownResult"
