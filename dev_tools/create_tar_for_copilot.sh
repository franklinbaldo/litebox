#!/bin/bash
# Create a tar archive for running GitHub Copilot CLI inside the litebox sandbox.
#
# Usage: ./dev_tools/create_tar_for_copilot_cli.sh [-o output.tar]
#
# Options:
#   -o FILE   Output tar path (default: /tmp/copilot_ustar.tar)
#
# Prerequisites:
#   - Build the packager: cargo build --release -p litebox_packager
#   - Copilot CLI installed (on PATH, or at ~/.local/bin/copilot)
#   - gh CLI auth configured (gh auth login)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGER="$REPO_ROOT/target/release/litebox_packager"
OUTPUT="/tmp/copilot_ustar.tar"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)       OUTPUT="$2"; shift 2 ;;
        *)        echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ ! -x "$PACKAGER" ]; then
    echo "Error: packager not found at $PACKAGER" >&2
    echo "Run: cargo build --release -p litebox_packager" >&2
    exit 1
fi

# --- Locate copilot binary ---
COPILOT_BIN="$(which copilot 2>/dev/null || true)"
if [ -z "$COPILOT_BIN" ] || [ ! -f "$COPILOT_BIN" ]; then
    echo "Error: copilot binary not found on PATH" >&2
    echo "Install: https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-the-copilot-subscription-for-your-organization/managing-your-github-copilot-enterprise-license" >&2
    exit 1
fi
echo "Copilot binary: $COPILOT_BIN"

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
# The native copilot launcher extracts its JS bundle to a cache directory.
# Respect the same env vars copilot uses: XDG_CACHE_HOME, then ~/.cache.
USER_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/copilot"
STAGING_DIR=""

if [ -d "$USER_CACHE_DIR/pkg" ]; then
    # Packages already extracted in the user's cache — use them directly.
    COPILOT_CACHE_DIR="$USER_CACHE_DIR"
    echo "Using cached packages: $COPILOT_CACHE_DIR/pkg"
else
    # Run copilot --help with a temp HOME to trigger package extraction.
    STAGING_DIR="$(mktemp -d)"
    echo "Extracting copilot packages to staging dir..."
    HOME="$STAGING_DIR" "$COPILOT_BIN" --help >/dev/null 2>&1 || true
    COPILOT_CACHE_DIR="$STAGING_DIR/.cache/copilot"
    if [ ! -d "$COPILOT_CACHE_DIR/pkg" ]; then
        echo "Error: copilot package extraction failed" >&2
        echo "Expected packages at $COPILOT_CACHE_DIR/pkg" >&2
        rm -rf "$STAGING_DIR"
        exit 1
    fi
fi
COPILOT_PKG_DIR="$COPILOT_CACHE_DIR/pkg"

# --- Temp files and cleanup ---
RESOLV_TMPFILE="$(mktemp)"
echo "nameserver 10.0.0.1" > "$RESOLV_TMPFILE"

cleanup() {
    rm -f "$RESOLV_TMPFILE"
    [ -n "$STAGING_DIR" ] && rm -rf "$STAGING_DIR"
}
trap cleanup EXIT

# --- Build include args ---

ARGS=()

# ELF binaries (auto-discovers shared lib dependencies via ldd)
ARGS+=("$COPILOT_BIN")
ARGS+=(/bin/bash /usr/bin/env /bin/dash)
ARGS+=(/usr/bin/git /usr/local/bin/gh)

# Common utilities that copilot spawns via the bash tool.
# Including them in the tar avoids the broker having to rewrite them on the fly.
ARGS+=(/usr/bin/ls /usr/bin/cat /usr/bin/ps /usr/bin/curl)

# git-remote-http is a separate ELF (not a symlink to git)
ARGS+=(/usr/lib/git-core/git-remote-http)

# Git subcommands that are symlinks to the main git binary.
# The packager resolves symlinks, so these become copies of the git ELF.
GIT_SYMLINK_CMDS=(
    checkout clone config fetch for-each-ref hash-object
    index-pack init ls-remote merge pack-objects reflog
    rev-parse symbolic-ref unpack-objects update-ref
)
for cmd in "${GIT_SYMLINK_CMDS[@]}"; do
    ARGS+=(--include "/usr/lib/git-core/git-$cmd:usr/lib/git-core/git-$cmd")
done
# git-remote-https is a symlink to git-remote-http
ARGS+=(--include "/usr/lib/git-core/git-remote-https:usr/lib/git-core/git-remote-https")

# NSS DNS module (loaded via dlopen, not discovered by ldd)
ARGS+=(--rewrite-include "/lib/x86_64-linux-gnu/libnss_dns.so.2:lib/x86_64-linux-gnu/libnss_dns.so.2")

# Shell symlink: /bin/sh -> dash (use --rewrite-include so it gets the
# syscall trampoline just like the /bin/dash copy from the positional args)
ARGS+=(--rewrite-include "/bin/sh:bin/sh")

# DNS and networking config
# Override resolv.conf: the host typically points at 127.0.0.53 (systemd-resolved)
# which doesn't exist inside the sandbox. Route DNS through the TUN gateway instead.
ARGS+=(--include "$RESOLV_TMPFILE:etc/resolv.conf")
ARGS+=(--include "/etc/host.conf:etc/host.conf")
ARGS+=(--include "/etc/gai.conf:etc/gai.conf")

# SSL CA certificates
ARGS+=(--include "/etc/ssl/certs/ca-certificates.crt:etc/ssl/certs/ca-certificates.crt")

# GitHub CLI auth
ARGS+=(--include "$GH_HOSTS:tmp/.config/gh/hosts.yml")

# Copilot config (auth tokens, model preferences, trusted folders)
if [ -f "$COPILOT_CONFIG_DIR/config.json" ]; then
    ARGS+=(--include "$COPILOT_CONFIG_DIR/config.json:tmp/.copilot/config.json")
fi

# Copilot package tree (JS, WASM, native .node modules, ripgrep, etc.)
while IFS= read -r -d '' file; do
    rel="${file#$COPILOT_CACHE_DIR/}"
    ARGS+=(--include "$file:tmp/.cache/copilot/$rel")
done < <(find "$COPILOT_PKG_DIR" -type f -print0)

# Output
ARGS+=(-o "$OUTPUT")

echo "Creating $OUTPUT ..."
"$PACKAGER" "${ARGS[@]}"
echo "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
