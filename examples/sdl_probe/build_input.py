#!/usr/bin/env python3

# Copyright (c) franklinbaldo.
# Licensed under the MIT license.

"""Build SDL keyboard fixture using the verified video build and an input patch."""
import os
import json
import subprocess
import build_video as video
from build import SDL_SRC, SDL_BUILD, get_zig_exe, check_prerequisites, ensure_sdl_source

def main():
    check_prerequisites()
    commit=ensure_sdl_source()
    video.apply_patch_idempotent()
    patch=os.path.join(video.PROBE_DIR,"litebox_input.patch")
    reverse=subprocess.run(["git","-C",SDL_SRC,"apply","--reverse","--check",patch],capture_output=True)
    if reverse.returncode:
        subprocess.run(["git","-C",SDL_SRC,"apply","--check",patch],check=True)
        subprocess.run(["git","-C",SDL_SRC,"apply",patch],check=True)
    zig=get_zig_exe()
    if not os.path.exists(os.path.join(SDL_BUILD,"build.ninja")):
        video.build_sdl_static(zig)
    video.build_sdl_incremental()
    video.SRC_C=os.path.join(video.PROBE_DIR,"input_probe.c")
    video.ELF_OUT=os.path.join(video.BOOTSTRAP_DIR,"input_probe.elf")
    video.HOOKED_OUT=os.path.join(video.BOOTSTRAP_DIR,"input_probe.hooked")
    video.TAR_OUT=os.path.join(video.BOOTSTRAP_DIR,"input-probe.tar")
    video.MANIFEST_OUT=os.path.join(video.BOOTSTRAP_DIR,"manifest_input.json")
    video.compile_probe(zig)
    video.rewrite_syscalls()
    video.package_tar()
    video.generate_manifest(commit)
    with open(video.MANIFEST_OUT, encoding="utf-8") as stream:
        manifest = json.load(stream)
    manifest["description"] = "LiteBox SDL2 keyboard and focus-release fixture (FDs 3/4)"
    for name, path in (("litebox_input_patch", patch), ("build_input_py", __file__)):
        manifest["files"][name] = {
            "path": os.path.relpath(path, video.ROOT_DIR),
            "sha256": video.compute_sha256(path),
            "size_bytes": os.path.getsize(path),
        }
    with open(video.MANIFEST_OUT, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)

if __name__=="__main__": main()
