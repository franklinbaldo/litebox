#!/usr/bin/env bash
set -euo pipefail

API="${ANDROID_API:-28}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-35.0.0}"
SYSTEM_IMAGE="${ANDROID_SYSTEM_IMAGE:-system-images;android-28;default;x86_64}"
WORK="$PWD/.android-work"
CACHE="$PWD/.android-smoke-cache"
EXTRACTED="$WORK/extracted"
ROOT="$WORK/android-root"
mkdir -p "$WORK" "$CACHE" "$EXTRACTED" "$ROOT"

sudo apt-get update
sudo apt-get install -y android-sdk-libsparse-utils e2fsprogs zip
SDKMANAGER="$(command -v sdkmanager || true)"
if test -z "$SDKMANAGER"; then
  for candidate in \
    "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
    "$ANDROID_HOME/cmdline-tools/bin/sdkmanager" \
    "$ANDROID_HOME/tools/bin/sdkmanager"; do
    if test -x "$candidate"; then
      SDKMANAGER="$candidate"
      break
    fi
  done
fi
if test -z "$SDKMANAGER"; then
  echo "sdkmanager not found under ANDROID_HOME=$ANDROID_HOME" >&2
  find "$ANDROID_HOME" -maxdepth 5 -type f -name sdkmanager -print >&2 || true
  exit 1
fi
yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
"$SDKMANAGER" "platforms;android-$API" "build-tools;$BUILD_TOOLS" "$SYSTEM_IMAGE"

cargo build --locked --release -p litebox_syscall_rewriter

system_img="$(find "$ANDROID_HOME/system-images/android-$API" -name system.img -print -quit)"
test -n "$system_img"
raw="$WORK/system.raw.img"
if ! simg2img "$system_img" "$raw"; then cp "$system_img" "$raw"; fi
debugfs -R "rdump / $EXTRACTED" "$raw"

if test -f "$EXTRACTED/bin/dalvikvm64"; then
  mkdir -p "$ROOT/system"
  cp -a "$EXTRACTED/." "$ROOT/system/"
elif test -f "$EXTRACTED/system/bin/dalvikvm64"; then
  cp -a "$EXTRACTED/." "$ROOT/"
else
  echo "dalvikvm64 not found in Android image" >&2
  find "$EXTRACTED" -maxdepth 4 -name 'dalvikvm*' -print >&2 || true
  exit 1
fi
test -f "$ROOT/system/bin/linker64"

bootclasspath=""
for candidate in "$EXTRACTED/init.environ.rc" "$ROOT/init.environ.rc" "$ROOT/system/etc/init/hw/init.environ.rc"; do
  if test -f "$candidate"; then
    bootclasspath="$(sed -n 's/^[[:space:]]*export BOOTCLASSPATH[[:space:]]*//p' "$candidate" | head -n1)"
    test -z "$bootclasspath" || break
  fi
done
if test -z "$bootclasspath"; then
  bootclasspath='/system/framework/core-oj.jar:/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/core-junit.jar:/system/framework/bouncycastle.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/apache-xml.jar:/system/framework/org.apache.http.legacy.boot.jar'
fi
printf '%s\n' "$bootclasspath" > "$CACHE/bootclasspath.txt"

apkout="$WORK/apk"
mkdir -p "$apkout/classes" "$apkout/dex"
javac -source 8 -target 8 -d "$apkout/classes" fixtures/android/ApkSmokeMain.java
"$ANDROID_HOME/build-tools/$BUILD_TOOLS/d8" --output "$apkout/dex" "$apkout/classes/dev/litebox/androidsmoke/ApkSmokeMain.class"
"$ANDROID_HOME/build-tools/$BUILD_TOOLS/aapt2" link -o "$apkout/litebox-smoke.apk" --manifest fixtures/android/AndroidManifest.xml -I "$ANDROID_HOME/platforms/android-$API/android.jar"
(cd "$apkout/dex" && zip -q "$apkout/litebox-smoke.apk" classes.dex)
unzip -l "$apkout/litebox-smoke.apk" | grep -E 'AndroidManifest.xml|classes.dex'
cp "$apkout/litebox-smoke.apk" "$CACHE/litebox-smoke.apk"

readelf_bin="$(command -v llvm-readelf || command -v readelf)"
args=(--android-root "$ROOT" --entry /system/bin/dalvikvm64 --extra /system/bin/linker64 --lib-dir /system/lib64 --readelf "$readelf_bin" --output "$WORK/runtime-raw.tar")
IFS=':' read -r -a boot_jars <<< "$bootclasspath"
for guest in "${boot_jars[@]}"; do
  test -f "$ROOT/${guest#/}" || { echo "BOOTCLASSPATH file missing: $guest" >&2; exit 1; }
  args+=(--extra "$guest")
done
python scripts/android/build_runtime_bundle.py "${args[@]}"
python scripts/android/finalize_litebox_bundle.py --input "$WORK/runtime-raw.tar" --output "$WORK/runtime-litebox.tar" --rewriter "$PWD/target/release/litebox_syscall_rewriter"

# ART boot OAT files are ELF containers with address-sensitive compiled code.
# Do not runtime-rewrite them merely because they have executable PT_LOAD
# segments. We only add LiteBox's existing size=0 sentinel when the normal
# rewriter proves that the file contains no syscall instructions; if it would
# change any code, the original file is preserved.
if test -d "$ROOT/system/framework/x86_64"; then
  ART_ROOT="$WORK/art-runtime-root"
  rm -rf "$ART_ROOT"
  mkdir -p "$ART_ROOT/system/framework"
  cp -a "$ROOT/system/framework/x86_64" "$ART_ROOT/system/framework/"
  while IFS= read -r -d '' oat; do
    python scripts/android/mark_no_syscall_elf.py \
      --input "$oat" \
      --rewriter "$PWD/target/release/litebox_syscall_rewriter"
  done < <(find "$ART_ROOT/system/framework/x86_64" -type f -name '*.oat' -print0)
  tar --format=gnu --append --file "$WORK/runtime-litebox.tar" -C "$ART_ROOT" system/framework/x86_64
fi
if test -d "$ROOT/system/usr/icu"; then
  tar --format=gnu --append --file "$WORK/runtime-litebox.tar" -C "$ROOT" system/usr/icu
fi

python scripts/android/prepare_apk_probe.py --runtime-tar "$WORK/runtime-litebox.tar" --apk "$CACHE/litebox-smoke.apk" --output "$CACHE/android-apk-smoke.tar"
sha256sum "$CACHE/android-apk-smoke.tar" "$CACHE/litebox-smoke.apk" > "$CACHE/SHA256SUMS"
cat "$CACHE/SHA256SUMS"
