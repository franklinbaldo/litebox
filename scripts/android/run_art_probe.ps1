param(
  [Parameter(Mandatory=$true)][string]$Tar,
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
  -cp /data/local/tmp/litebox-art-probe.jar `
  dev.litebox.ArtHello

if ($LASTEXITCODE -ne 0) {
  throw "Android ART probe failed with exit code $LASTEXITCODE"
}
