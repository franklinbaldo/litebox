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
sudo apt-get install -y android-sdk-libsparse-utils e2fsprogs parted zip
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
rm -f "$raw"
if ! simg2img "$system_img" "$raw"; then
  cp "$system_img" "$raw"
fi

# Android SDK system images have existed both as a direct ext filesystem and
# as a raw GPT disk image. debugfs unfortunately reports success even when it
# sees a GPT header, so detect the disk label first instead of trusting its
# process status.
fs_image="$raw"
partition_table="$(parted -ms "$raw" unit B print 2>/dev/null || true)"
disk_label="$(printf '%s\n' "$partition_table" | awk -F: 'NR == 2 { print $6 }')"
if test "$disk_label" = "gpt" || test "$disk_label" = "msdos"; then
  partition="$(
    printf '%s\n' "$partition_table" \
      | awk -F: '$1 ~ /^[0-9]+$/ && $5 ~ /^ext[234]$/ { print $2, $3; exit }'
  )"
  if test -z "$partition"; then
    partition="$(
      printf '%s\n' "$partition_table" \
        | awk -F: '$1 ~ /^[0-9]+$/ { print $2, $3; exit }'
    )"
  fi
  if test -z "$partition"; then
    echo "partitioned system.img contains no extractable partition" >&2
    printf '%s\n' "$partition_table" >&2
    exit 1
  fi

  read -r start end <<< "$partition"
  start="${start%B}"
  end="${end%B}"
  fs_image="$WORK/system.fs.img"
  python - "$raw" "$fs_image" "$start" "$end" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
start = int(sys.argv[3])
end = int(sys.argv[4])
remaining = end - start + 1
if start < 0 or remaining <= 0:
    raise SystemExit(f"invalid partition byte range: {start}..{end}")

with source.open("rb") as src, target.open("wb") as dst:
    src.seek(start)
    while remaining:
        chunk = src.read(min(8 * 1024 * 1024, remaining))
        if not chunk:
            raise SystemExit("unexpected EOF while extracting system partition")
        dst.write(chunk)
        remaining -= len(chunk)
PY
fi

# Validate that the selected/extracted object really is an ext filesystem.
debugfs -R stats "$fs_image" 2>&1 | tee "$WORK/debugfs-stats.log"
if grep -Eq 'Bad magic number|Filesystem not open|Found a .* partition table' "$WORK/debugfs-stats.log"; then
  echo "selected system filesystem is not readable by debugfs" >&2
  exit 1
fi

# Preserve Android ownership and mode bits exactly. Some metadata files are
# intentionally unreadable to an ordinary user, so extraction runs privileged;
# changing ownership/modes would mutate the guest filesystem semantics.
sudo debugfs -R "rdump / $EXTRACTED" "$fs_image"

if test -f "$EXTRACTED/bin/dalvikvm64"; then
  # Older images expose the system partition itself as the filesystem root.
  mkdir -p "$ROOT/system"
  sudo cp -a "$EXTRACTED/." "$ROOT/system/"
elif test -f "$EXTRACTED/system/bin/dalvikvm64"; then
  # API 28's current SDK image already contains the /system directory. Use it
  # directly instead of copying the complete multi-gigabyte extracted tree.
  ROOT="$EXTRACTED"
else
  echo "dalvikvm64 not found in Android image" >&2
  sudo find "$EXTRACTED" -maxdepth 4 -name 'dalvikvm*' -print >&2 || true
  exit 1
fi
test -f "$ROOT/system/bin/linker64"

bootclasspath=""
for candidate in "$EXTRACTED/init.environ.rc" "$ROOT/init.environ.rc" "$ROOT/system/etc/init/hw/init.environ.rc"; do
  if test -r "$candidate"; then
    bootclasspath="$(sed -n 's/^[[:space:]]*export BOOTCLASSPATH[[:space:]]*//p' "$candidate" | head -n1)"
    test -z "$bootclasspath" || break
  fi
done

# init.environ.rc lives in the boot ramdisk on this SDK image, not system.img.
# Reconstruct Pie's PRODUCT_BOOT_JARS order from the actual installed jars.
# TARGET_CORE_JARS for this generation is the six-module prefix below; Pie then
# appends framework/HIDL jars and one member of each compatibility pair.
if test -z "$bootclasspath"; then
  boot_paths=()
  required_modules=(
    core-oj
    core-libart
    conscrypt
    okhttp
    bouncycastle
    apache-xml
    ext
    framework
    telephony-common
    voip-common
    ims-common
    android.hidl.base-V1.0-java
    android.hidl.manager-V1.0-java
  )
  for module in "${required_modules[@]}"; do
    guest="/system/framework/$module.jar"
    if ! test -f "$ROOT/${guest#/}"; then
      echo "Pie BOOTCLASSPATH module missing from image: $guest" >&2
      exit 1
    fi
    boot_paths+=("$guest")
  done

  if test -f "$ROOT/system/framework/org.apache.http.legacy.boot.jar"; then
    boot_paths+=(/system/framework/org.apache.http.legacy.boot.jar)
  elif test -f "$ROOT/system/framework/framework-oahl-backward-compatibility.jar"; then
    boot_paths+=(/system/framework/framework-oahl-backward-compatibility.jar)
  else
    echo "Pie BOOTCLASSPATH is missing both OAHL alternatives" >&2
    exit 1
  fi

  if test -f "$ROOT/system/framework/android.test.base.jar"; then
    boot_paths+=(/system/framework/android.test.base.jar)
  elif test -f "$ROOT/system/framework/framework-atb-backward-compatibility.jar"; then
    boot_paths+=(/system/framework/framework-atb-backward-compatibility.jar)
  else
    echo "Pie BOOTCLASSPATH is missing both android.test.base alternatives" >&2
    exit 1
  fi

  bootclasspath="$(IFS=:; printf '%s' "${boot_paths[*]}")"
fi
printf '%s\n' "$bootclasspath" > "$CACHE/bootclasspath.txt"
echo "BOOTCLASSPATH=$bootclasspath"

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
