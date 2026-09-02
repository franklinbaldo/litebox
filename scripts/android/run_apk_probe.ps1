param(
  [Parameter(Mandatory=$true)][string]$Tar,
  [Parameter(Mandatory=$true)][string]$MainClass,
  [string]$LiteBox = "litebox",
  [string]$ArtEntry = "/apex/com.android.art/bin/dalvikvm64"
)

$ErrorActionPreference = "Stop"

& $LiteBox run `
  --env ANDROID_DATA=/data `
  --env ANDROID_ROOT=/system `
  --env ANDROID_ART_ROOT=/apex/com.android.art `
  $Tar `
  $ArtEntry `
  -cp /data/local/tmp/litebox-apk-smoke.apk `
  $MainClass

if ($LASTEXITCODE -ne 0) {
  throw "Android APK smoke failed with exit code $LASTEXITCODE"
}
