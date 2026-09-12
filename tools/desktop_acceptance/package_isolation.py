#!/usr/bin/env python3

# Copyright (c) franklinbaldo.
# Licensed under the MIT license.

"""Installer integration test with inert fixtures, never launched as games.

All writes stay in a newly allocated target/ directory. Tests package lifecycle,
not guest persistence or compatibility with real games. Requires a built launcher.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]
EXE = REPO / "tools/litebox_launcher/target/release/litebox_launcher.exe"


def main():
    base = REPO / "target/desktop-acceptance"
    base.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="package isolation ", dir=base))
    root = workspace / "installed games"
    results = []

    def call(*args, success=True):
        run = subprocess.run([str(EXE), *map(str, args), "--root", str(root)],
                             capture_output=True, text=True, timeout=30)
        results.append({"args": list(map(str, args)), "exit": run.returncode,
                        "stdout": run.stdout, "stderr": run.stderr})
        assert (run.returncode == 0) == success, results[-1]

    def fixture(game_id, version="1.0.0", profile="demo_stdio_v1"):
        folder = workspace / f"source-{game_id}-{version}"
        folder.mkdir()
        files = []
        for name in ["host.exe", "runner.exe", "content.tar", "icon.ico", "LICENSE.txt"]:
            data = f"Inert installer fixture: {name}\n".encode()
            (folder / name).write_bytes(data)
            files.append({"path": name, "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
        manifest = {"schema_version": 1, "id": game_id, "name": f"Fixture {game_id}",
                    "version": version, "runtime": {"profile": profile,
                    "required_features": [], "host": "host.exe", "runner": "runner.exe"},
                    "content": "content.tar", "icon": "icon.ico", "files": files}
        (folder / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        return folder

    # Unsupported runtime is rejected before creating an installation root.
    call("install", fixture("needs-gl", profile="desktop_fd_v1"), success=False)
    assert not root.exists()
    first = fixture("fixture-one")
    second = fixture("fixture-two")
    call("install", first)
    call("install", second)
    for game in ["fixture-one", "fixture-two"]:
        assert (root / f"shortcuts/{game} - LiteBox.lnk").is_file()
        assert json.loads((root / f"state/{game}.json").read_text())["version"] == "1.0.0"
    saved = root / "data/fixture-one/host-data-sentinel.txt"
    saved.write_text("preserve me", encoding="utf-8")
    call("install", fixture("fixture-one", "2.0.0"))
    assert json.loads((root / "state/fixture-one.json").read_text())["version"] == "2.0.0"
    assert json.loads((root / "state/fixture-two.json").read_text())["version"] == "1.0.0"
    # Invalid interrupted update rolls back to the previous verified version.
    (root / "state/fixture-one.pending.json").write_text(json.dumps({
        "previous": {"version": "2.0.0"}, "next": {"version": "missing"}}))
    call("install", first, success=False)
    assert json.loads((root / "state/fixture-one.json").read_text())["version"] == "2.0.0"
    call("uninstall", "../fixture-two", success=False)
    (first / "content.tar").write_bytes(b"corrupt")
    call("install", first, success=False)
    call("uninstall", "fixture-one")
    assert saved.read_text() == "preserve me"
    assert not (root / "shortcuts/fixture-one - LiteBox.lnk").exists()
    assert not (root / "state/fixture-one.json").exists()
    assert (root / "shortcuts/fixture-two - LiteBox.lnk").is_file()
    assert (root / "packages/fixture-two/1.0.0/content.tar").is_file()
    assert (root / "state/fixture-two.json").is_file()
    call("uninstall", "fixture-two")
    output = workspace / "results.json"
    output.write_text(json.dumps({"passed": True, "scope": "inert package lifecycle only",
                                  "calls": results}, indent=2), encoding="utf-8")
    print(f"PASS: two-package isolation, update, recovery, hashes, traversal, retained host data. {output}")


if __name__ == "__main__":
    main()
