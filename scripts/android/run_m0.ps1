param(
  [Parameter(Mandatory=$true)][string]$Tar,
  [string]$LiteBox = "litebox"
)

$ErrorActionPreference = "Stop"

& $LiteBox run $Tar /system/bin/litebox-android-hello
if ($LASTEXITCODE -ne 0) {
  throw "Android M0 probe failed with exit code $LASTEXITCODE"
}
