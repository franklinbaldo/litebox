#!/usr/bin/env python3
"""
build_audio.py - Builds the experimental LiteBox audio probe with dedicated FDs (5/6).
Reuses functions and configuration from examples/sdl_probe/build.py.

Steps:
1. Verifies prerequisites and upstream SDL2 source.
2. Applies examples/sdl_probe/litebox_audio.patch idempotently with base verification.
3. Incrementally builds libSDL2.a using Ninja.
4. Compiles examples/sdl_probe/audio_probe.c to target/sdl-bootstrap/audio_probe.elf.
5. Rewrites syscalls using litebox_syscall_rewriter.exe -> audio_probe.hooked.
6. Packages into target/sdl-bootstrap/audio-probe.tar as /bin/probe (USTAR, mode 0755).
7. Generates target/sdl-bootstrap/manifest_audio.json.
(Does NOT execute in the normal runner because normal runner does not supply dedicated audio FDs 5/6).
"""

import os
import sys
import json
import tarfile
import subprocess
import argparse

# Import shared functions and paths from build.py
PROBE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROBE_DIR)
from build import (
    ROOT_DIR,
    BOOTSTRAP_DIR,
    SDL_SRC,
    SDL_BUILD,
    SDL_LIB,
    REWRITER_BIN,
    SDL_GIT_TAG,
    check_prerequisites,
    ensure_sdl_source,
    get_zig_exe,
    compute_sha256,
    build_sdl_static,
)

SRC_C = os.path.join(PROBE_DIR, "audio_probe.c")
PATCH_FILE = os.path.join(PROBE_DIR, "litebox_audio.patch")
ELF_OUT = os.path.join(BOOTSTRAP_DIR, "audio_probe.elf")
HOOKED_OUT = os.path.join(BOOTSTRAP_DIR, "audio_probe.hooked")
TAR_OUT = os.path.join(BOOTSTRAP_DIR, "audio-probe.tar")
MANIFEST_OUT = os.path.join(BOOTSTRAP_DIR, "manifest_audio.json")


def apply_patch_idempotent():
    print(f"[*] Checking patch status: {PATCH_FILE}...")
    if not os.path.exists(PATCH_FILE):
        raise FileNotFoundError(f"Patch file not found: {PATCH_FILE}")

    # Check if already applied (reverse check passes)
    res_rev = subprocess.run(
        ["git", "-C", SDL_SRC, "apply", "--reverse", "--check", PATCH_FILE],
        capture_output=True, text=True
    )
    if res_rev.returncode == 0:
        print("[+] Patch is already applied to SDL source.")
        return

    # Verify forward patch applies cleanly
    res_fwd = subprocess.run(
        ["git", "-C", SDL_SRC, "apply", "--check", PATCH_FILE],
        capture_output=True, text=True
    )
    if res_fwd.returncode != 0:
        print(f"ERROR: Cannot apply patch to {SDL_SRC} (base mismatch or dirty tree).")
        print("Git error:", res_fwd.stderr)
        sys.exit(1)

    # Apply patch
    subprocess.run(
        ["git", "-C", SDL_SRC, "apply", PATCH_FILE],
        check=True
    )
    print("[+] Successfully applied litebox_audio.patch to SDL source.")


def build_sdl_incremental():
    print(f"[*] Rebuilding libSDL2.a incrementally with Ninja...")
    build_cmd = ["ninja", "-C", SDL_BUILD, "SDL2-static"]
    subprocess.run(build_cmd, check=True)
    print(f"[+] libSDL2.a updated: {SDL_LIB} ({os.path.getsize(SDL_LIB)} bytes)")


def compile_probe(zig_exe):
    print(f"[*] Compiling {SRC_C} into {ELF_OUT}...")
    include_dirs = [
        os.path.join(SDL_SRC, "include"),
        os.path.join(SDL_BUILD, "include"),
        os.path.join(SDL_BUILD, "include-config-release"),
    ]
    cmd = [
        zig_exe, "cc",
        "-target", "x86_64-linux-musl",
        "-static",
        "-O2",
    ]
    for inc in include_dirs:
        if os.path.exists(inc):
            cmd.extend(["-I", inc])
            cmd.extend(["-I", os.path.join(inc, "SDL2")])

    cmd.extend([
        SRC_C,
        SDL_LIB,
        "-o", ELF_OUT
    ])
    subprocess.run(cmd, check=True)
    print(f"[+] Compiled ELF: {ELF_OUT} ({os.path.getsize(ELF_OUT)} bytes)")


def rewrite_syscalls():
    print(f"[*] Rewriting syscalls with {REWRITER_BIN}...")
    cmd = [REWRITER_BIN, ELF_OUT, "-o", HOOKED_OUT]
    subprocess.run(cmd, check=True)
    print(f"[+] Rewritten ELF: {HOOKED_OUT} ({os.path.getsize(HOOKED_OUT)} bytes)")


def package_tar():
    print(f"[*] Packaging tar rootfs to {TAR_OUT} (USTAR format, entry: bin/probe)...")
    with tarfile.open(TAR_OUT, "w", format=tarfile.USTAR_FORMAT) as tar:
        ti = tar.gettarinfo(HOOKED_OUT, arcname="bin/probe")
        ti.mode = 0o755
        ti.uid = 0
        ti.gid = 0
        ti.uname = "root"
        ti.gname = "root"
        with open(HOOKED_OUT, "rb") as f:
            tar.addfile(ti, f)
    print(f"[+] Created TAR archive: {TAR_OUT} ({os.path.getsize(TAR_OUT)} bytes)")


def generate_manifest(sdl_commit):
    manifest = {
        "description": "LiteBox SDL2 experimental real audio probe (desktop_fd_v1, FDs 5/6)",
        "sdl_git_tag": SDL_GIT_TAG,
        "sdl_git_commit": sdl_commit,
        "files": {
            "audio_probe_c": {
                "path": os.path.relpath(SRC_C, ROOT_DIR),
                "sha256": compute_sha256(SRC_C),
                "size_bytes": os.path.getsize(SRC_C),
            },
            "litebox_audio_patch": {
                "path": os.path.relpath(PATCH_FILE, ROOT_DIR),
                "sha256": compute_sha256(PATCH_FILE),
                "size_bytes": os.path.getsize(PATCH_FILE),
            },
            "build_audio_py": {
                "path": os.path.relpath(__file__, ROOT_DIR),
                "sha256": compute_sha256(__file__),
                "size_bytes": os.path.getsize(__file__),
            },
            "libSDL2_a": {
                "path": os.path.relpath(SDL_LIB, ROOT_DIR),
                "sha256": compute_sha256(SDL_LIB),
                "size_bytes": os.path.getsize(SDL_LIB),
            },
            "audio_probe_elf": {
                "path": os.path.relpath(ELF_OUT, ROOT_DIR),
                "sha256": compute_sha256(ELF_OUT),
                "size_bytes": os.path.getsize(ELF_OUT),
            },
            "audio_probe_hooked": {
                "path": os.path.relpath(HOOKED_OUT, ROOT_DIR),
                "sha256": compute_sha256(HOOKED_OUT),
                "size_bytes": os.path.getsize(HOOKED_OUT),
            },
            "audio_probe_tar": {
                "path": os.path.relpath(TAR_OUT, ROOT_DIR),
                "sha256": compute_sha256(TAR_OUT),
                "size_bytes": os.path.getsize(TAR_OUT),
            },
            "rewriter_bin": {
                "path": REWRITER_BIN,
                "sha256": compute_sha256(REWRITER_BIN),
                "size_bytes": os.path.getsize(REWRITER_BIN),
            },
        }
    }
    with open(MANIFEST_OUT, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Audio build manifest saved: {MANIFEST_OUT}")


def main():
    parser = argparse.ArgumentParser(description="Builds experimental LiteBox audio probe")
    parser.parse_args()

    check_prerequisites()
    sdl_commit = ensure_sdl_source()
    zig_exe = get_zig_exe()
    print(f"[+] Using zig executable: {zig_exe}")

    apply_patch_idempotent()
    if not os.path.exists(os.path.join(SDL_BUILD, "build.ninja")):
        build_sdl_static(zig_exe)
    build_sdl_incremental()
    compile_probe(zig_exe)
    rewrite_syscalls()
    package_tar()
    generate_manifest(sdl_commit)
    print("\n[+] Done! Artifact ready: target/sdl-bootstrap/audio-probe.tar")


if __name__ == "__main__":
    main()
