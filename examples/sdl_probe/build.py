#!/usr/bin/env python3
"""
build.py - Builds and tests the minimal SDL2 probe for LiteBox on Windows.
Reuses the recipe and tools from examples/linux_game/build.py.

Steps:
1. Validates or downloads official SDL2 source (git tag release-2.30.12).
2. Cross-compiles static libSDL2.a for x86_64-linux-musl using CMake + Ninja + zig cc.
3. Compiles examples/sdl_probe/main.c into a static Linux musl ELF binary.
4. Rewrites syscalls using litebox_syscall_rewriter.exe.
5. Packages into target/sdl-bootstrap/probe.tar (USTAR format, mode 0755).
6. Executes with litebox_runner_linux_on_windows_userland.exe and captures output.
"""

import os
import sys
import json
import hashlib
import subprocess
import tarfile
import argparse

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROBE_DIR = os.path.join(ROOT_DIR, "examples", "sdl_probe")
SRC_C = os.path.join(PROBE_DIR, "main.c")
BOOTSTRAP_DIR = os.path.abspath(os.environ.get("SDL_BOOTSTRAP_DIR", os.path.join(ROOT_DIR, "target", "sdl-bootstrap")))
SDL_SRC = os.path.join(BOOTSTRAP_DIR, "SDL")
SDL_BUILD = os.path.join(BOOTSTRAP_DIR, "build")
SDL_LIB = os.path.join(SDL_BUILD, "libSDL2.a")

ELF_OUT = os.path.join(BOOTSTRAP_DIR, "sdl_probe.elf")
HOOKED_OUT = os.path.join(BOOTSTRAP_DIR, "sdl_probe.hooked")
TAR_OUT = os.path.join(BOOTSTRAP_DIR, "probe.tar")
MANIFEST_OUT = os.path.join(BOOTSTRAP_DIR, "manifest.json")

ORIGINAL_RELEASE = os.environ.get("LITEBOX_TOOLS_DIR", os.path.join(ROOT_DIR, "target", "debug"))
LOCAL_RELEASE = os.path.join(ROOT_DIR, "target", "release")

SDL_GIT_TAG = "release-2.30.12"
SDL_GIT_REPO = "https://github.com/libsdl-org/SDL.git"


def find_tool(name):
    # Check original read-only repo first as requested
    p1 = os.path.join(ORIGINAL_RELEASE, name)
    if os.path.exists(p1):
        return p1
    p2 = os.path.join(LOCAL_RELEASE, name)
    if os.path.exists(p2):
        return p2
    return p1


REWRITER_BIN = find_tool("litebox_syscall_rewriter.exe")
RUNNER_BIN = find_tool("litebox_runner_linux_on_windows_userland.exe")


def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_zig_exe():
    try:
        import ziglang
        p = os.path.join(os.path.dirname(ziglang.__file__), "zig.exe")
        if os.path.exists(p):
            return p
    except ImportError:
        pass
    # Try finding via uv
    res = subprocess.run(
        ["uv", "run", "--with", "ziglang==0.13.0", "python", "-c",
         "import ziglang, os; print(os.path.join(os.path.dirname(ziglang.__file__), 'zig.exe'))"],
        capture_output=True, text=True, check=True
    )
    return res.stdout.strip()


def check_prerequisites():
    if not os.path.exists(REWRITER_BIN):
        print(f"ERROR: Syscall rewriter not found at {REWRITER_BIN}")
        sys.exit(1)
    if not os.path.exists(RUNNER_BIN):
        print(f"ERROR: Runner not found at {RUNNER_BIN}")
        sys.exit(1)
    print(f"[+] Found rewriter: {REWRITER_BIN}")
    print(f"[+] Found runner: {RUNNER_BIN}")


def ensure_sdl_source():
    os.makedirs(BOOTSTRAP_DIR, exist_ok=True)
    if not os.path.exists(SDL_SRC):
        print(f"[*] Cloning official SDL2 tag {SDL_GIT_TAG} from {SDL_GIT_REPO}...")
        cmd = [
            "git", "clone", "--depth", "1",
            "--branch", SDL_GIT_TAG,
            SDL_GIT_REPO, SDL_SRC
        ]
        subprocess.run(cmd, check=True)

    # Get and log git commit hash
    res = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=SDL_SRC, capture_output=True, text=True, check=True
    )
    commit = res.stdout.strip()
    if commit != "8236e01a9f758d15927624925c6043f84d8a261f":
        raise RuntimeError("Unexpected SDL source commit: " + commit)
    print(f"[+] SDL2 upstream tag: {SDL_GIT_TAG} (commit {commit})")
    return commit


def build_sdl_static(zig_exe):
    if os.path.exists(SDL_LIB):
        print(f"[+] Using existing libSDL2.a: {SDL_LIB} ({os.path.getsize(SDL_LIB)} bytes)")
        return

    print("[*] Generating zig compiler wrappers for CMake...")
    bat_cc = os.path.join(BOOTSTRAP_DIR, "zig-cc.bat")
    bat_ar = os.path.join(BOOTSTRAP_DIR, "zig-ar.bat")
    bat_ranlib = os.path.join(BOOTSTRAP_DIR, "zig-ranlib.bat")

    with open(bat_cc, "w") as f:
        f.write(f'@echo off\n"{zig_exe}" cc -target x86_64-linux-musl %*\n')
    with open(bat_ar, "w") as f:
        f.write(f'@echo off\n"{zig_exe}" ar %*\n')
    with open(bat_ranlib, "w") as f:
        f.write(f'@echo off\n"{zig_exe}" ranlib %*\n')

    print("[*] Configuring SDL2 with CMake (musl static minimal dummy build)...")
    os.makedirs(SDL_BUILD, exist_ok=True)

    cmake_cmd = [
        "cmake", "-G", "Ninja",
        "-S", SDL_SRC,
        "-B", SDL_BUILD,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_SYSTEM_NAME=Linux",
        "-DCMAKE_SYSTEM_PROCESSOR=x86_64",
        f"-DCMAKE_C_COMPILER={bat_cc.replace(os.sep, '/')}",
        f"-DCMAKE_AR={bat_ar.replace(os.sep, '/')}",
        f"-DCMAKE_RANLIB={bat_ranlib.replace(os.sep, '/')}",
        "-DSDL_SHARED=OFF",
        "-DSDL_STATIC=ON",
        "-DSDL_TEST=OFF",
        "-DSDL_TESTS=OFF",
        "-DSDL2_DISABLE_SDL2MAIN=ON",
        "-DSDL2_DISABLE_INSTALL=ON",
        "-DSDL2_DISABLE_UNINSTALL=ON",
        "-DSDL_ASSEMBLY=OFF",
        "-DSDL_X11=OFF",
        "-DSDL_WAYLAND=OFF",
        "-DSDL_ALSA=OFF",
        "-DSDL_PULSEAUDIO=OFF",
        "-DSDL_JACK=OFF",
        "-DSDL_PIPEWIRE=OFF",
        "-DSDL_OSS=OFF",
        "-DSDL_OPENGL=OFF",
        "-DSDL_OPENGLES=OFF",
        "-DSDL_VULKAN=OFF",
        "-DSDL_KMSDRM=OFF",
        "-DSDL_DIRECTFB=OFF",
        "-DSDL_DBUS=OFF",
        "-DSDL_IBUS=OFF",
        "-DSDL_LIBUDEV=OFF",
        "-DSDL_DISKAUDIO=OFF",
        "-DSDL_DUMMYAUDIO=ON",
        "-DSDL_DUMMYVIDEO=ON",
        "-DSDL_OFFSCREEN=OFF",
        "-DSDL_CCACHE=OFF",
        "-DSDL_HIDAPI=OFF",
        "-DSDL_POWER=OFF",
        "-DSDL_SENSOR=OFF",
        "-DSDL_HAPTIC=OFF",
        "-DSDL_JOYSTICK=OFF",
    ]
    subprocess.run(cmake_cmd, check=True)

    print("[*] Building target SDL2-static with Ninja...")
    build_cmd = ["ninja", "-C", SDL_BUILD, "SDL2-static"]
    subprocess.run(build_cmd, check=True)
    print(f"[+] libSDL2.a built successfully: {SDL_LIB} ({os.path.getsize(SDL_LIB)} bytes)")


def compile_probe(zig_exe):
    print(f"[*] Compiling {SRC_C} with SDL2 static into {ELF_OUT}...")
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
    print(f"[*] Packaging tar rootfs to {TAR_OUT} (USTAR format, mode 0755)...")
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


def run_in_litebox():
    print(f"[*] Executing via LiteBox runner: {RUNNER_BIN} --initial-files {TAR_OUT} /bin/probe")
    cmd = [RUNNER_BIN, "--initial-files", TAR_OUT, "/bin/probe"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("=== LITEBOX RUNNER OUTPUT ===")
    print("STDOUT:")
    print(res.stdout)
    print("STDERR:")
    print(res.stderr)
    print(f"Exit Code: {res.returncode}")
    print("=============================")
    return res


def generate_manifest(sdl_commit):
    manifest = {
        "sdl_git_tag": SDL_GIT_TAG,
        "sdl_git_commit": sdl_commit,
        "files": {
            "main_c": {
                "path": os.path.relpath(SRC_C, ROOT_DIR),
                "sha256": compute_sha256(SRC_C),
                "size_bytes": os.path.getsize(SRC_C),
            },
            "build_py": {
                "path": os.path.relpath(__file__, ROOT_DIR),
                "sha256": compute_sha256(__file__),
                "size_bytes": os.path.getsize(__file__),
            },
            "libSDL2_a": {
                "path": os.path.relpath(SDL_LIB, ROOT_DIR),
                "sha256": compute_sha256(SDL_LIB),
                "size_bytes": os.path.getsize(SDL_LIB),
            },
            "probe_elf": {
                "path": os.path.relpath(ELF_OUT, ROOT_DIR),
                "sha256": compute_sha256(ELF_OUT),
                "size_bytes": os.path.getsize(ELF_OUT),
            },
            "probe_hooked": {
                "path": os.path.relpath(HOOKED_OUT, ROOT_DIR),
                "sha256": compute_sha256(HOOKED_OUT),
                "size_bytes": os.path.getsize(HOOKED_OUT),
            },
            "probe_tar": {
                "path": os.path.relpath(TAR_OUT, ROOT_DIR),
                "sha256": compute_sha256(TAR_OUT),
                "size_bytes": os.path.getsize(TAR_OUT),
            },
            "runner_bin": {
                "path": RUNNER_BIN,
                "sha256": compute_sha256(RUNNER_BIN),
                "size_bytes": os.path.getsize(RUNNER_BIN),
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
    print(f"[+] Build manifest saved: {MANIFEST_OUT}")


def main():
    parser = argparse.ArgumentParser(description="SDL2 probe builder and runner for LiteBox")
    parser.add_argument("--no-run", action="store_true", help="Skip running in LiteBox")
    args = parser.parse_args()

    check_prerequisites()
    sdl_commit = ensure_sdl_source()
    zig_exe = get_zig_exe()
    print(f"[+] Using zig executable: {zig_exe}")

    build_sdl_static(zig_exe)
    compile_probe(zig_exe)
    rewrite_syscalls()
    package_tar()
    generate_manifest(sdl_commit)

    if not args.no_run:
        res = run_in_litebox()
        if res.returncode != 0:
            print(f"[!] Warning: Runner exited with non-zero code {res.returncode}")
            sys.exit(res.returncode)


if __name__ == "__main__":
    main()
