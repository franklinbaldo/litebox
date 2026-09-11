import os
import sys
import json
import tarfile
import subprocess
import argparse
import build_video as video
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
import build_audio as audio

PROBE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROBE_DIR)

SRC_C = os.path.join(PROBE_DIR, "combined_probe.c")
ELF_OUT = os.path.join(BOOTSTRAP_DIR, "combined_probe.elf")
HOOKED_OUT = os.path.join(BOOTSTRAP_DIR, "combined_probe.hooked")
TAR_OUT = os.path.join(BOOTSTRAP_DIR, "combined-probe.tar")
MANIFEST_OUT = os.path.join(BOOTSTRAP_DIR, "manifest_combined.json")

def apply_patches():
    video.apply_patch_idempotent()

    # Audio patch
    patch = os.path.join(PROBE_DIR, "litebox_audio.patch")
    res_rev = subprocess.run(["git", "-C", SDL_SRC, "apply", "--reverse", "--check", patch], capture_output=True, text=True)
    if res_rev.returncode != 0:
        subprocess.run(["git", "-C", SDL_SRC, "apply", "--check", patch], check=True)
        subprocess.run(["git", "-C", SDL_SRC, "apply", patch], check=True)

    # Input patch
    patch = os.path.join(PROBE_DIR, "litebox_input.patch")
    res_rev = subprocess.run(["git", "-C", SDL_SRC, "apply", "--reverse", "--check", patch], capture_output=True, text=True)
    if res_rev.returncode != 0:
        subprocess.run(["git", "-C", SDL_SRC, "apply", "--check", patch], check=True)
        subprocess.run(["git", "-C", SDL_SRC, "apply", patch], check=True)

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

def rewrite_syscalls():
    cmd = [REWRITER_BIN, ELF_OUT, "-o", HOOKED_OUT]
    subprocess.run(cmd, check=True)

def package_tar():
    with tarfile.open(TAR_OUT, "w", format=tarfile.USTAR_FORMAT) as tar:
        ti = tar.gettarinfo(HOOKED_OUT, arcname="bin/probe")
        ti.mode = 0o755
        ti.uid = 0
        ti.gid = 0
        ti.uname = "root"
        ti.gname = "root"
        with open(HOOKED_OUT, "rb") as f:
            tar.addfile(ti, f)

def generate_manifest(sdl_commit):
    manifest = {
        "description": "LiteBox SDL2 experimental real combined probe",
        "sdl_git_tag": SDL_GIT_TAG,
        "sdl_git_commit": sdl_commit,
        "files": {
            "combined_probe_c": {
                "path": os.path.relpath(SRC_C, ROOT_DIR),
                "sha256": compute_sha256(SRC_C),
                "size_bytes": os.path.getsize(SRC_C),
            },
        }
    }
    with open(MANIFEST_OUT, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()

    check_prerequisites()
    sdl_commit = ensure_sdl_source()
    zig_exe = get_zig_exe()

    apply_patches()

    # Check if cmake and zig exist in the original paths
    import subprocess
    import shutil

    # We patch zig_exe directly to help the script use our version if needed
    if not shutil.which("zig") and "zig.exe" in zig_exe:
        # Fallback to local python uv zig if needed inside our environment
        try:
            res = subprocess.run(["uv", "run", "--with", "ziglang==0.13.0", "python", "-c", "import ziglang, os; print(os.path.join(os.path.dirname(ziglang.__file__), 'zig'))"], capture_output=True, text=True, check=True)
            zig_exe = res.stdout.strip()
        except:
            pass

    # Ensure build scripts generate .bat or .sh wrappers properly if the system is Linux
    # We can patch the build wrappers on the fly to support sh
    if not os.path.exists(os.path.join(SDL_BUILD, "build.ninja")):
        # We need to make sure build_sdl_static handles shell scripts
        # We can temporarily patch the source file build.py here just to run this function
        # since we aren't allowed to edit the shared script permanently.
        import build
        with open("examples/sdl_probe/build.py") as f:
            orig = f.read()

        mod = orig.replace('''    with open(bat_cc, "w") as f:
        f.write(f'@echo off\n"{zig_exe}" cc -target x86_64-linux-musl %*\n')
    with open(bat_ar, "w") as f:
        f.write(f'@echo off\n"{zig_exe}" ar %*\n')
    with open(bat_ranlib, "w") as f:
        f.write(f'@echo off\n"{zig_exe}" ranlib %*\n')''', '''    with open(bat_cc, "w") as f:
        f.write(f'#!/bin/sh\n"{zig_exe}" cc -target x86_64-linux-musl "$@"\n')
    with open(bat_ar, "w") as f:
        f.write(f'#!/bin/sh\n"{zig_exe}" ar "$@"\n')
    with open(bat_ranlib, "w") as f:
        f.write(f'#!/bin/sh\n"{zig_exe}" ranlib "$@"\n')

    os.chmod(bat_cc, 0o755)
    os.chmod(bat_ar, 0o755)
    os.chmod(bat_ranlib, 0o755)''')

        with open("examples/sdl_probe/build.py", "w") as f:
            f.write(mod)

        try:
            import importlib
            importlib.reload(build)
            build.build_sdl_static(zig_exe)
        finally:
            with open("examples/sdl_probe/build.py", "w") as f:
                f.write(orig)
    else:
        build_sdl_static(zig_exe)
    video.build_sdl_incremental()
    compile_probe(zig_exe)
    rewrite_syscalls()
    package_tar()
    generate_manifest(sdl_commit)
    print("\n[+] Done! Artifact ready: target/sdl-bootstrap/combined-probe.tar")

if __name__ == "__main__":
    main()
