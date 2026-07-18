$ErrorActionPreference = "Stop"

$repositoryRoot = $PSScriptRoot
$miraiRoot = (Resolve-Path (Join-Path $repositoryRoot "..\..\MIRAI")).Path
$mirai = (Resolve-Path (Join-Path $miraiRoot "target\debug\mirai.exe")).Path
$target = Join-Path $repositoryRoot "target\mirai-double-lock"
$manifest = Join-Path $repositoryRoot "Cargo.toml"
$originalPath = $env:PATH
$originalWrapper = $env:RUSTC_WORKSPACE_WRAPPER
$originalTarget = $env:CARGO_TARGET_DIR
$originalJobs = $env:CARGO_BUILD_JOBS
$originalShare = $env:MIRAI_SHARE_PERSISTENT_STORE
$originalFlags = $env:MIRAI_FLAGS
$originalLog = $env:MIRAI_LOG

$contracts = @(
    "litebox.mirai_contracts.acquire_descriptor_write",
    "litebox.mirai_contracts.release_descriptor_write",
    "litebox.mirai_contracts.require_no_descriptor_writer"
)
$rows = [ordered]@{
    "pre_fix" = @{
        key = "litebox_shim_linux.syscalls.net.implement_litebox_shim_linux_GlobalState_generic_par_FS.mirai_setsockopt_pre_fix"
        expected = "set_tcp_option requires no live descriptor writer"
    }
    "fixed" = @{
        key = "litebox_shim_linux.syscalls.net.implement_litebox_shim_linux_GlobalState_generic_par_FS.mirai_setsockopt_fixed"
        expected = $null
    }
    "unrelated_lock" = @{
        key = "litebox_shim_linux.syscalls.net.implement_litebox_shim_linux_GlobalState_generic_par_FS.mirai_setsockopt_unrelated_lock"
        expected = $null
    }
}

try {
    Set-Location $repositoryRoot
    $sysroot = (& rustup run nightly-2026-06-01 rustc --print sysroot).Trim()
    $env:PATH = "$(Join-Path $sysroot "bin");$originalPath"
    $env:RUSTC_WORKSPACE_WRAPPER = $mirai
    $env:CARGO_TARGET_DIR = $target
    $env:CARGO_BUILD_JOBS = "1"
    $env:MIRAI_SHARE_PERSISTENT_STORE = "true"

    if (Test-Path $target) {
        Remove-Item -Recurse -Force $target
    }

    foreach ($contract in $contracts) {
        $env:MIRAI_FLAGS = "--single_func $contract --print_summaries"
        $env:MIRAI_LOG = $null
        & cargo clean --quiet --manifest-path $manifest --target-dir $target -p litebox
        & cargo check --locked -q --manifest-path $manifest -p litebox --features mirai 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to seed $contract (exit $LASTEXITCODE)."
        }
    }

    $passed = 0
    foreach ($entry in $rows.GetEnumerator()) {
        $name = $entry.Key
        $key = $entry.Value.key
        $expected = $entry.Value.expected
        $env:MIRAI_FLAGS = "--single_func $key"
        $env:MIRAI_LOG = $null

        # The first pass creates callback-specialized HOF summaries.
        & cargo clean --quiet --manifest-path $manifest --target-dir $target -p litebox_shim_linux
        & cargo check --locked -q --manifest-path $manifest -p litebox_shim_linux `
            --no-default-features --features platform_windows_userland,mirai 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to seed $name (exit $LASTEXITCODE)."
        }

        # The second pass must consume persisted summaries without entering protected bodies.
        $env:MIRAI_LOG = "mirai::summaries=trace,mirai::body_visitor=debug"
        & cargo clean --quiet --manifest-path $manifest --target-dir $target -p litebox_shim_linux
        $output = @(
            & cargo check --locked -q --manifest-path $manifest -p litebox_shim_linux `
                --no-default-features --features platform_windows_userland,mirai 2>&1
        )
        $exitCode = $LASTEXITCODE
        $diagnostics = @($output | Where-Object { $_ -match "^warning: \[MIRAI\]" })
        $loads = @($output | Where-Object {
            $_ -match "get_persistent_summary_for_db\(\) => Some\(Summary"
        })
        $bodyEntries = @($output | Where-Object {
            $_ -match "entered body of .*mirai_contracts" -or
            $_ -match "entered body of .*mirai_with_descriptor_write" -or
            $_ -match "entered body of .*mirai_setsockopt_(pre_fix|fixed|unrelated_lock).*closure"
        })

        if ($null -eq $expected) {
            $matchesExpectation = $exitCode -eq 0 -and $diagnostics.Count -eq 0
            $expectedText = "silent"
        } else {
            $matching = @($diagnostics | Where-Object { $_ -like "*$expected*" })
            $matchesExpectation = $exitCode -eq 0 -and
                $diagnostics.Count -eq 1 -and
                $matching.Count -eq 1
            $expectedText = $expected
        }
        $matchesExpectation = $matchesExpectation -and
            $loads.Count -gt 0 -and
            $bodyEntries.Count -eq 0

        $actual = if ($diagnostics.Count -eq 0) {
            "silent"
        } elseif ($diagnostics.Count -eq 1) {
            $diagnostics[0] -replace "^warning: \[MIRAI\] ", ""
        } else {
            "$($diagnostics.Count) MIRAI diagnostics"
        }
        $status = if ($matchesExpectation) { "PASS" } else { "FAIL" }
        Write-Host "$status $name - expected: $expectedText; actual: $actual; persisted loads: $($loads.Count); protected body entries: $($bodyEntries.Count)"
        if (-not $matchesExpectation) {
            $output | ForEach-Object { Write-Host $_ }
        } else {
            $passed++
        }
    }

    Write-Host "$passed/$($rows.Count) passed"
    if ($passed -ne $rows.Count) {
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
    Set-Location $repositoryRoot
}
