$ErrorActionPreference = "Stop"

# These opt-in XFAIL rows are deliberately excluded from run_mirai_double_lock.ps1. They isolate
# two independent summary limits: incomplete nested-HOF summaries and model-field writes through a
# returned reference losing their parameter root. An XPASS/FAIL means either MIRAI gained a
# capability or its internal log format changed; investigate before removing or tightening this.

$repositoryRoot = $PSScriptRoot
$miraiRoot = (Resolve-Path (Join-Path $repositoryRoot "..\..\MIRAI")).Path
$mirai = (Resolve-Path (Join-Path $miraiRoot "target\debug\mirai.exe")).Path
$target = Join-Path $repositoryRoot "target\mirai-known-limits"
$manifest = Join-Path $repositoryRoot "Cargo.toml"
$originalPath = $env:PATH
$originalWrapper = $env:RUSTC_WORKSPACE_WRAPPER
$originalTarget = $env:CARGO_TARGET_DIR
$originalJobs = $env:CARGO_BUILD_JOBS
$originalShare = $env:MIRAI_SHARE_PERSISTENT_STORE
$originalFlags = $env:MIRAI_FLAGS
$originalLog = $env:MIRAI_LOG
$originalStartFresh = $env:MIRAI_START_FRESH

$rows = @(
    @{
        name = "real_path_incomplete_summary"
        feature = "mirai_real_path_tripwire"
        key = "litebox_shim_linux.syscalls.net.implement_litebox_shim_linux_GlobalState_generic_par_FS.mirai_real_path_tripwire"
        expectedDiagnostic = "callback invocation could not be resolved"
        expectedSummary = "is_incomplete: true"
    },
    @{
        name = "descriptor_rekey_empty_pre_state"
        feature = "mirai_descriptor_rekey_tripwire"
        key = "litebox_shim_linux.syscalls.net.implement_litebox_shim_linux_GlobalState_generic_par_FS.mirai_descriptor_rekey_tripwire"
        expectedDiagnostic = $null
        expectedSummary = "pre_state: []"
    }
)

try {
    Set-Location $repositoryRoot
    $sysroot = (& rustup run nightly-2026-06-01 rustc --print sysroot).Trim()
    $env:PATH = "$(Join-Path $sysroot "bin");$originalPath"
    $env:RUSTC_WORKSPACE_WRAPPER = $mirai
    $env:CARGO_TARGET_DIR = $target
    $env:CARGO_BUILD_JOBS = "1"
    $env:MIRAI_SHARE_PERSISTENT_STORE = "true"
    $env:MIRAI_START_FRESH = $null

    if (Test-Path $target) {
        Remove-Item -Recurse -Force $target
    }

    $observed = 0
    foreach ($row in $rows) {
        $features = "platform_windows_userland,$($row.feature)"
        $env:MIRAI_FLAGS = "--single_func $($row.key)"
        $env:MIRAI_LOG = $null

        & cargo clean --quiet --manifest-path $manifest --target-dir $target -p litebox_shim_linux
        $seedOutput = @(
            & cargo check --locked -q --manifest-path $manifest -p litebox_shim_linux `
                --no-default-features --features $features 2>&1
        )
        if ($LASTEXITCODE -ne 0) {
            $seedOutput | ForEach-Object { Write-Host $_ }
            throw "Failed to seed $($row.name) (exit $LASTEXITCODE)."
        }

        $env:MIRAI_LOG = "mirai::summaries=trace,mirai::body_visitor=debug"
        & cargo clean --quiet --manifest-path $manifest --target-dir $target -p litebox_shim_linux
        $output = @(
            & cargo check --locked -q --manifest-path $manifest -p litebox_shim_linux `
                --no-default-features --features $features 2>&1
        )
        $exitCode = $LASTEXITCODE
        $diagnostics = @($output | Where-Object { $_ -match "^warning: \[MIRAI\]" })
        $loads = @($output | Where-Object {
            $_ -match "get_persistent_summary_for_db\(\) => Some\(Summary"
        })
        $summaryMatches = @($loads | Where-Object {
            $_.ToString().Contains($row.expectedSummary)
        })
        $bodyEntries = @($output | Where-Object {
            $_ -match "entered body of .*with_socket_options_mut" -or
            $_ -match "entered body of .*with_metadata_mut" -or
            $_ -match "entered body of .*mirai_with_descriptor_write" -or
            $_ -match "entered body of .*mirai_contracts"
        })

        if ($null -eq $row.expectedDiagnostic) {
            $matchesDiagnostic = $diagnostics.Count -eq 0
            $actual = "silent"
        } else {
            $matching = @($diagnostics | Where-Object { $_ -like "*$($row.expectedDiagnostic)*" })
            $matchesDiagnostic = $diagnostics.Count -eq 1 -and $matching.Count -eq 1
            $actual = if ($diagnostics.Count -eq 1) {
                $diagnostics[0] -replace "^warning: \[MIRAI\] ", ""
            } else {
                "$($diagnostics.Count) MIRAI diagnostics"
            }
        }

        $matchesKnownLimit = $exitCode -eq 0 -and
            $matchesDiagnostic -and
            $loads.Count -gt 0 -and
            $summaryMatches.Count -gt 0 -and
            $bodyEntries.Count -eq 0
        $status = if ($matchesKnownLimit) { "XFAIL" } else { "XPASS/FAIL" }
        Write-Host "$status $($row.name) - actual: $actual; summary signal: $($row.expectedSummary); persisted loads: $($loads.Count); protected body entries: $($bodyEntries.Count)"

        if ($matchesKnownLimit) {
            $observed++
        } else {
            $output | ForEach-Object { Write-Host $_ }
        }
    }

    Write-Host "$observed/$($rows.Count) known limitations observed"
    if ($observed -ne $rows.Count) {
        exit 1
    }
} finally {
    $env:PATH = $originalPath
    $env:RUSTC_WORKSPACE_WRAPPER = $originalWrapper
    $env:CARGO_TARGET_DIR = $originalTarget
    $env:CARGO_BUILD_JOBS = $originalJobs
    $env:MIRAI_SHARE_PERSISTENT_STORE = $originalShare
    $env:MIRAI_FLAGS = $originalFlags
    $env:MIRAI_LOG = $originalLog
    $env:MIRAI_START_FRESH = $originalStartFresh
    Set-Location $repositoryRoot
}
