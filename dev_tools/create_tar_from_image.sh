#!/bin/bash
# Create a tar archive for running GitHub Copilot CLI inside the litebox sandbox,
# extracting the copilot binary from the container image instead of requiring a
# host installation.
#
# Usage: ./dev_tools/create_tar_from_image.sh [-o output.tar] [--ipc] [--home DIR]
#                                              [--image IMAGE]
#
# Options:
#   -o FILE       Output tar path (default: /tmp/copilot_ustar.tar)
#   --ipc         Use IPC network proxy (DNS via 8.8.8.8 instead of TUN gateway)
#   --home DIR    Home directory path inside the sandbox (default: $HOME)
#   --image IMAGE Container image to extract copilot from
#                 (default: ghcr.io/henrybravo/docker-sandbox-run-copilot)
#
# Prerequisites:
#   - Build the packager: cargo build --release -p litebox_packager
#   - podman or docker available
#   - gh CLI auth configured (gh auth login)
#
# This script does NOT require copilot to be installed on the host.
# It pulls the copilot native binary from the container image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGER="$REPO_ROOT/target/release/litebox_packager"
OUTPUT="/tmp/copilot_ustar.tar"
USE_IPC=false
SANDBOX_HOME="${SANDBOX_HOME:-$HOME}"
IMAGE="${COPILOT_IMAGE:-ghcr.io/henrybravo/docker-sandbox-run-copilot}"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/litebox"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)       OUTPUT="$2"; shift 2 ;;
        --ipc)    USE_IPC=true; shift ;;
        --home)   SANDBOX_HOME="$2"; shift 2 ;;
        --image)  IMAGE="$2"; shift 2 ;;
        *)        echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ ! -x "$PACKAGER" ]; then
    echo "Error: packager not found at $PACKAGER" >&2
    echo "Run: cargo build --release -p litebox_packager" >&2
    exit 1
fi

# --- Detect container runtime ------------------------------------------------
CONTAINER_RT=""
if command -v podman &>/dev/null; then
    CONTAINER_RT=podman
elif command -v docker &>/dev/null; then
    CONTAINER_RT=docker
else
    echo "Error: neither podman nor docker found on PATH" >&2
    exit 1
fi
echo "Container runtime: $CONTAINER_RT"

# --- Extract copilot binary from container image -----------------------------
# The native copilot binary lives at a well-known path inside the image.
IMAGE_COPILOT_PATH="/usr/lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-x64/copilot"

mkdir -p "$CACHE_DIR"
COPILOT_BIN="$CACHE_DIR/copilot-from-image"

# Re-extract if the cached binary is missing or the image has been updated.
extract_needed=true
if [ -x "$COPILOT_BIN" ]; then
    # Check if image digest changed since last extraction.
    SAVED_DIGEST="$CACHE_DIR/copilot-image-digest"
    CURRENT_DIGEST=$($CONTAINER_RT image inspect "$IMAGE" --format '{{.Digest}}' 2>/dev/null || true)
    if [ -n "$CURRENT_DIGEST" ] && [ -f "$SAVED_DIGEST" ] && [ "$(cat "$SAVED_DIGEST")" = "$CURRENT_DIGEST" ]; then
        echo "Using cached copilot binary: $COPILOT_BIN"
        extract_needed=false
    fi
fi

if [ "$extract_needed" = true ]; then
    echo "Pulling image: $IMAGE"
    $CONTAINER_RT pull "$IMAGE"

    echo "Extracting copilot binary..."
    cid=$($CONTAINER_RT create "$IMAGE")
    $CONTAINER_RT cp "$cid:$IMAGE_COPILOT_PATH" "$COPILOT_BIN"
    $CONTAINER_RT rm "$cid" > /dev/null
    chmod +x "$COPILOT_BIN"

    # Save digest for cache invalidation.
    $CONTAINER_RT image inspect "$IMAGE" --format '{{.Digest}}' > "$CACHE_DIR/copilot-image-digest" 2>/dev/null || true

    echo "Extracted: $COPILOT_BIN ($(du -h "$COPILOT_BIN" | cut -f1))"
fi

# Verify the binary is a valid ELF.
if ! file "$COPILOT_BIN" | grep -q "ELF 64-bit"; then
    echo "Error: extracted binary is not a valid x86-64 ELF" >&2
    exit 1
fi

# Quick smoke test.
COPILOT_VERSION=$("$COPILOT_BIN" --version 2>&1 || true)
echo "Copilot version: $COPILOT_VERSION"

# --- Locate gh CLI auth ---
GH_HOSTS="${GH_CONFIG_DIR:-$HOME/.config/gh}/hosts.yml"
if [ ! -f "$GH_HOSTS" ]; then
    echo "Error: gh auth config not found at $GH_HOSTS" >&2
    echo "Run: gh auth login" >&2
    exit 1
fi

# --- Locate copilot config ---
COPILOT_CONFIG_DIR="${COPILOT_DATA_DIR:-$HOME/.copilot}"

# --- Locate or extract copilot JS package ---
# The native binary is self-contained but extracts a JS/WASM package bundle
# on first run into ~/.copilot/pkg (or ~/.cache/copilot/pkg for older versions).
COPILOT_DATA="${COPILOT_DATA_DIR:-$HOME/.copilot}"
LEGACY_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/copilot"
STAGING_DIR=""

if [ -d "$COPILOT_DATA/pkg" ]; then
    COPILOT_CACHE_DIR="$COPILOT_DATA"
    echo "Using cached packages: $COPILOT_CACHE_DIR/pkg"
elif [ -d "$LEGACY_CACHE_DIR/pkg" ]; then
    COPILOT_CACHE_DIR="$LEGACY_CACHE_DIR"
    echo "Using cached packages (legacy path): $COPILOT_CACHE_DIR/pkg"
else
    # Run copilot --help with a temp HOME to trigger package extraction.
    STAGING_DIR="$(mktemp -d)"
    echo "Extracting copilot packages to staging dir..."
    HOME="$STAGING_DIR" "$COPILOT_BIN" --help >/dev/null 2>&1 || true
    # Check both possible extraction paths.
    if [ -d "$STAGING_DIR/.copilot/pkg" ]; then
        COPILOT_CACHE_DIR="$STAGING_DIR/.copilot"
    elif [ -d "$STAGING_DIR/.cache/copilot/pkg" ]; then
        COPILOT_CACHE_DIR="$STAGING_DIR/.cache/copilot"
    else
        echo "Error: copilot package extraction failed" >&2
        echo "Checked: $STAGING_DIR/.copilot/pkg" >&2
        echo "Checked: $STAGING_DIR/.cache/copilot/pkg" >&2
        rm -rf "$STAGING_DIR"
        exit 1
    fi
fi
COPILOT_PKG_DIR="$COPILOT_CACHE_DIR/pkg"

# --- Temp files and cleanup ---
RESOLV_TMPFILE="$(mktemp)"
if $USE_IPC; then
    echo "nameserver 8.8.8.8" > "$RESOLV_TMPFILE"
    echo "DNS: 8.8.8.8 (IPC network proxy mode)"
else
    echo "nameserver 10.0.0.1" > "$RESOLV_TMPFILE"
    echo "DNS: 10.0.0.1 (TUN gateway mode)"
fi

cleanup() {
    rm -f "$RESOLV_TMPFILE"
    if [ -n "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
}
trap cleanup EXIT

declare -A SEEN_SHARED_DEPS=()
declare -A REPORTED_MISSING_DEPS=()

mark_ldd_deps_seen() {
    local elf="$1"
    while IFS= read -r dep; do
        [ -n "$dep" ] || continue
        SEEN_SHARED_DEPS["$dep"]=1
    done < <(
        ldd "$elf" 2>/dev/null | awk '
            /=> \// { print $3 }
            /^[[:space:]]*\/[^[:space:]]+/ { print $1 }
        '
    )
}

append_missing_rewrite_dep() {
    local dep="$1"
    [ -n "$dep" ] || return 0
    if [[ -n "${SEEN_SHARED_DEPS[$dep]:-}" ]]; then
        return 0
    fi
    SEEN_SHARED_DEPS["$dep"]=1
    ARGS+=(--rewrite-include "$dep:${dep#/}")
}

report_missing_dep_once() {
    local dep="$1"
    local source_file="$2"
    [ -n "$dep" ] || return 0
    if [[ -n "${REPORTED_MISSING_DEPS[$dep]:-}" ]]; then
        return 0
    fi
    REPORTED_MISSING_DEPS["$dep"]=1
    echo "WARN: missing shared library $dep (referenced by $source_file)" >&2
}

append_pkg_native_deps() {
    local file
    while IFS= read -r -d '' file; do
        local info
        info="$(file -b "$file" 2>/dev/null || true)"
        case "$info" in
            *"ELF 64-bit LSB"*x86-64*)
                ;;
            *)
                continue
                ;;
        esac

        while IFS= read -r dep; do
            [ -n "$dep" ] || continue
            case "$dep" in
                WARN:*)
                    report_missing_dep_once "${dep#WARN:}" "$file"
                    ;;
                *)
                    append_missing_rewrite_dep "$dep"
                    ;;
            esac
        done < <(
            ldd "$file" 2>/dev/null | awk '
                /=> \// { print $3 }
                /=> not found/ { print "WARN:" $1 }
                /^[[:space:]]*\/[^[:space:]]+/ { print $1 }
            '
        )
    done < <(
        find "$COPILOT_PKG_DIR" -type f \
            \( -name '*.node' -o -path '*/ripgrep/bin/linux-x64/rg' \) \
            -print0
    )
}

# --- Build include args ---

ARGS=()
BASE_ELF_INPUTS=()

# ELF binaries (auto-discovers shared lib dependencies via ldd)
BASE_ELF_INPUTS+=("$COPILOT_BIN")
BASE_ELF_INPUTS+=(/bin/bash /usr/bin/env /bin/dash)

# gh and git from host (still needed for git operations)
if command -v git &>/dev/null; then
    BASE_ELF_INPUTS+=(/usr/bin/git)
fi
if command -v gh &>/dev/null; then
    GH_BIN="$(which gh)"
    BASE_ELF_INPUTS+=("$GH_BIN")
fi

# Common utilities that copilot spawns via the bash tool.
for util in /usr/bin/ls /usr/bin/cat /usr/bin/ps /usr/bin/curl; do
    [ -x "$util" ] && BASE_ELF_INPUTS+=("$util")
done

# git-remote-http is a separate ELF (not a symlink to git)
[ -x /usr/lib/git-core/git-remote-http ] && BASE_ELF_INPUTS+=(/usr/lib/git-core/git-remote-http)

for elf in "${BASE_ELF_INPUTS[@]}"; do
    ARGS+=("$elf")
    mark_ldd_deps_seen "$elf"
done

# Git subcommands that are symlinks to the main git binary.
GIT_SYMLINK_CMDS=(
    checkout clone config fetch for-each-ref hash-object
    index-pack init ls-remote merge pack-objects reflog
    rev-parse symbolic-ref unpack-objects update-ref
)
for cmd in "${GIT_SYMLINK_CMDS[@]}"; do
    [ -e "/usr/lib/git-core/git-$cmd" ] && \
        ARGS+=(--include "/usr/lib/git-core/git-$cmd:usr/lib/git-core/git-$cmd")
done
# git-remote-https is a symlink to git-remote-http
[ -e /usr/lib/git-core/git-remote-https ] && \
    ARGS+=(--include "/usr/lib/git-core/git-remote-https:usr/lib/git-core/git-remote-https")

# NSS DNS module (loaded via dlopen, not discovered by ldd)
[ -f /lib/x86_64-linux-gnu/libnss_dns.so.2 ] && \
    ARGS+=(--rewrite-include "/lib/x86_64-linux-gnu/libnss_dns.so.2:lib/x86_64-linux-gnu/libnss_dns.so.2")

# Shell symlink: /bin/sh -> dash
ARGS+=(--rewrite-include "/bin/sh:bin/sh")

# DNS and networking config
ARGS+=(--include "$RESOLV_TMPFILE:etc/resolv.conf")
[ -f /etc/host.conf ] && ARGS+=(--include "/etc/host.conf:etc/host.conf")
[ -f /etc/gai.conf ] && ARGS+=(--include "/etc/gai.conf:etc/gai.conf")

# SSL CA certificates
ARGS+=(--include "/etc/ssl/certs/ca-certificates.crt:etc/ssl/certs/ca-certificates.crt")

# Home-relative paths
TAR_HOME="${SANDBOX_HOME#/}"

# GitHub CLI auth
ARGS+=(--include "$GH_HOSTS:$TAR_HOME/.config/gh/hosts.yml")

# Copilot config (auth tokens, model preferences, trusted folders)
if [ -f "$COPILOT_CONFIG_DIR/config.json" ]; then
    ARGS+=(--include "$COPILOT_CONFIG_DIR/config.json:$TAR_HOME/.copilot/config.json")
fi

# Copilot package tree (JS, WASM, native .node modules, ripgrep, etc.)
while IFS= read -r -d '' file; do
    rel="${file#$COPILOT_CACHE_DIR/}"
    ARGS+=(--include "$file:$TAR_HOME/.cache/copilot/$rel")
done < <(find "$COPILOT_PKG_DIR" -type f -print0)

# Native .node modules and bundled ELF tools
append_pkg_native_deps

# Output
ARGS+=(-o "$OUTPUT")

echo "Creating $OUTPUT ..."
"$PACKAGER" "${ARGS[@]}"
echo "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
echo ""
echo "Run with:"
echo "  COPILOT_TAR=$OUTPUT ./dev_tools/run_copilot_ipc.sh"
echo ""
echo "Or set the COPILOT_BIN override for run_copilot_ipc.sh:"
echo "  COPILOT_TAR=$OUTPUT COPILOT_BIN=$COPILOT_BIN ./dev_tools/run_copilot_ipc.sh"
