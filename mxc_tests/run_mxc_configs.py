#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path

PYTHON_SCRIPT_RE = re.compile(r'^python -c "(?P<code>.*)"$', re.DOTALL)
IMPORT_SYS_RE = re.compile(r"(^|\n)\s*(import sys\b|from sys import\b)")
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\"'\n]+")
DEFAULT_BROKER_ROOT = Path("C:\\")
COLORAMA_STUB = """import sys
import types
try:
    import colorama  # noqa: F401
except ImportError:
    mod = types.ModuleType("colorama")
    mod.Fore = types.SimpleNamespace(GREEN="", RED="")
    mod.Style = types.SimpleNamespace(RESET_ALL="")
    sys.modules["colorama"] = mod
"""


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_output_dir() -> Path:
    return Path(tempfile.gettempdir()) / "litebox-mxc"


def default_broker_endpoint() -> str:
    return str(default_output_dir() / "mxc-broker.sock")


def parse_args() -> argparse.Namespace:
    root = repo_root()
    output_dir = default_output_dir()
    parser = argparse.ArgumentParser(
        description="Run the Python-based MXC configs under LiteBox on Windows.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        required=True,
        help="Path to microsoft/mxc/test_configs",
    )
    parser.add_argument(
        "--python-tar",
        type=Path,
        required=True,
        help="Path to the LiteBox-packaged Python rootfs tar",
    )
    parser.add_argument(
        "--broker",
        type=Path,
        default=root / "target" / "release" / "litebox_broker.exe",
        help="Path to litebox_broker.exe",
    )
    parser.add_argument(
        "--runner",
        type=Path,
        default=root / "target" / "release" / "litebox_runner_linux_on_windows_userland.exe",
        help="Path to litebox_runner_linux_on_windows_userland.exe",
    )
    parser.add_argument(
        "--broker-endpoint",
        default=default_broker_endpoint(),
        help="Broker listen/connect endpoint. Defaults to a temporary AF_UNIX socket path",
    )
    parser.add_argument(
        "--broker-root",
        type=Path,
        default=DEFAULT_BROKER_ROOT,
        help="Host root directory exposed through the broker-backed 9P mount",
    )
    parser.add_argument(
        "--broker-log",
        type=Path,
        default=output_dir / "mxc-broker.log",
        help="Path to the broker log file",
    )
    parser.add_argument(
        "--results-path",
        type=Path,
        default=output_dir / "mxc-results.json",
        help="Path to the JSON summary written by the harness",
    )
    return parser.parse_args()


def normalize_code(name: str, code: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    if "sys." in code and not IMPORT_SYS_RE.search(code):
        code = "import sys\n" + code
        notes.append("prepended missing import sys")
    if "from colorama import Fore, Style" in code:
        code = COLORAMA_STUB + "\n" + code
        notes.append("injected colorama fallback stub")
    return code, notes


def extract_windows_paths(text: str) -> list[str]:
    return sorted(set(WINDOWS_PATH_RE.findall(text)), key=len, reverse=True)


def normalize_windows_source_path(path: str) -> str:
    return path.replace("\\\\", "\\")


def windows_path_to_guest(path: str) -> str:
    path = normalize_windows_source_path(path)
    if len(path) < 3 or path[1] != ':' or path[2] not in ('\\', '/'):
        return path
    drive = path[0].upper()
    if drive != 'C':
        raise ValueError(f"unsupported non-C drive path in MXC harness: {path}")
    rest = path[2:].replace('\\', '/')
    return '/' + rest.lstrip('/')


def prepare_host_files(name: str, code: str) -> list[str]:
    notes: list[str] = []
    for windows_path in extract_windows_paths(code):
        windows_path = normalize_windows_source_path(windows_path)
        if not windows_path.lower().startswith("c:\\temp\\"):
            continue
        host_path = Path(windows_path)
        host_path.parent.mkdir(parents=True, exist_ok=True)
        if name == "filesystem_bfs_readonly_test.json" and host_path.name == "test_input.txt":
            host_path.write_text("seed input", encoding="utf-8")
            notes.append("seeded readonly input file on host")
    return notes


def rewrite_windows_paths(code: str) -> tuple[str, list[str]]:
    replaced = False
    for windows_path in extract_windows_paths(code):
        guest_path = windows_path_to_guest(windows_path)
        if guest_path != windows_path:
            code = code.replace(windows_path, guest_path)
            replaced = True
    notes = ["mapped Windows paths to broker-backed guest paths"] if replaced else []
    return code, notes


def writable_paths_for_config(data: dict) -> list[str]:
    filesystem = data.get("filesystem")
    if not isinstance(filesystem, dict):
        return []
    paths = filesystem.get("readwritePaths", [])
    return [path for path in paths if isinstance(path, str)]


def cleanup_unix_endpoint(endpoint: str) -> None:
    if endpoint.count(':') == 1 and endpoint.split(':', 1)[1].isdigit():
        return
    try:
        Path(endpoint).unlink()
    except FileNotFoundError:
        pass


def stop_broker(
    proc: subprocess.Popen[str] | None,
    broker_log,
    broker_endpoint: str,
) -> None:
    if proc is None:
        if broker_log is not None:
            broker_log.close()
        cleanup_unix_endpoint(broker_endpoint)
        return

    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
    finally:
        if broker_log is not None:
            broker_log.close()
        cleanup_unix_endpoint(broker_endpoint)


def endpoint_is_tcp(endpoint: str) -> bool:
    try:
        host, port_str = endpoint.rsplit(":", 1)
        port = int(port_str)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        socket.getaddrinfo(host, port)
        return True
    except (OSError, ValueError):
        return False


def start_broker(
    broker_path: Path,
    broker_endpoint: str,
    broker_root: Path,
    writable_paths: list[str],
    broker_log_path: Path,
    log_label: str,
) -> tuple[subprocess.Popen[str], object, str]:
    if not broker_path.is_file():
        raise FileNotFoundError(f"broker not found: {broker_path}")
    if not broker_root.is_dir():
        raise FileNotFoundError(f"broker root not found: {broker_root}")

    broker_log_path.parent.mkdir(parents=True, exist_ok=True)
    cleanup_unix_endpoint(broker_endpoint)
    broker_log = broker_log_path.open("a", encoding="utf-8")
    broker_log.write(f"\n=== {log_label} ===\n")
    broker_log.flush()

    cmd = [
        str(broker_path),
        "--network-proxy-listen",
        broker_endpoint,
        "--root-dir",
        str(broker_root),
        "--read-only",
    ]
    for writable_path in writable_paths:
        cmd.extend(["--writable-path", writable_path])

    proc = subprocess.Popen(
        cmd,
        stdout=broker_log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.time() + 10.0
        last_error = None
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"broker exited early with code {proc.returncode}; see {broker_log_path}"
                )
            try:
                if endpoint_is_tcp(broker_endpoint):
                    host, port_str = broker_endpoint.rsplit(":", 1)
                    if host.startswith("[") and host.endswith("]"):
                        host = host[1:-1]
                    with socket.create_connection((host, int(port_str)), timeout=0.2):
                        return proc, broker_log, broker_endpoint
                else:
                    if Path(broker_endpoint).exists():
                        time.sleep(0.2)
                        return proc, broker_log, broker_endpoint
                time.sleep(0.1)
            except OSError as exc:
                last_error = exc
                time.sleep(0.1)
        raise TimeoutError(
            f"broker did not start listening at {broker_endpoint}: {last_error}"
        )
    except Exception:
        stop_broker(proc, broker_log, broker_endpoint)
        raise


def run_config(
    path: Path,
    runner_path: Path,
    broker_path: Path,
    broker_endpoint: str,
    broker_root: Path,
    broker_log_path: Path,
    python_tar: Path,
) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    script = data.get("script", "").strip()
    match = PYTHON_SCRIPT_RE.fullmatch(script)
    if not match:
        return {
            "name": path.name,
            "status": "skipped",
            "reason": "non-python script",
            "notes": [],
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "semantic_warning": False,
        }

    code, notes = normalize_code(path.name, match.group("code"))
    notes.extend(prepare_host_files(path.name, code))
    code, path_notes = rewrite_windows_paths(code)
    notes.extend(path_notes)
    writable_paths = writable_paths_for_config(data)
    timeout_s = (data.get("timeout", 15_000) / 1000.0) + 5.0

    broker_proc = None
    broker_log = None
    try:
        broker_proc, broker_log, broker_endpoint = start_broker(
            broker_path,
            broker_endpoint,
            broker_root,
            writable_paths,
            broker_log_path,
            path.name,
        )
        cmd = [
            str(runner_path),
            "--unstable",
            "--network-broker",
            broker_endpoint,
            "--nine-p-broker",
            broker_endpoint,
            "--initial-files",
            str(python_tar),
            "/usr/local/bin/python3",
            "-c",
            code,
        ]
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "name": path.name,
            "status": "failed",
            "reason": f"timed out after {timeout_s:.1f}s",
            "notes": notes,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "semantic_warning": False,
        }
    finally:
        stop_broker(broker_proc, broker_log, broker_endpoint)

    stdout = completed.stdout
    stderr = completed.stderr
    semantic_warning = "ERROR:" in stdout or "Error:" in stdout
    status = "ok" if completed.returncode == 0 else "failed"
    return {
        "name": path.name,
        "status": status,
        "reason": "",
        "notes": notes,
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "semantic_warning": semantic_warning,
    }


def print_result(result: dict) -> None:
    detail = ""
    if result["returncode"] is not None:
        detail = f" rc={result['returncode']}"
    if result["reason"]:
        detail += f" ({result['reason']})"
    if result["notes"]:
        detail += f" notes={'; '.join(result['notes'])}"
    print(f"[{result['status']}] {result['name']}{detail}", flush=True)


def main() -> None:
    args = parse_args()
    if not args.config_dir.is_dir():
        raise FileNotFoundError(f"config directory not found: {args.config_dir}")
    if not args.python_tar.is_file():
        raise FileNotFoundError(f"python tar not found: {args.python_tar}")
    if not args.runner.is_file():
        raise FileNotFoundError(f"runner not found: {args.runner}")

    args.broker_log.parent.mkdir(parents=True, exist_ok=True)
    args.broker_log.write_text("", encoding="utf-8")

    results = []
    for path in sorted(args.config_dir.glob("*.json")):
        result = run_config(
            path,
            args.runner,
            args.broker,
            args.broker_endpoint,
            args.broker_root,
            args.broker_log,
            args.python_tar,
        )
        results.append(result)
        print_result(result)

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    ok = 0
    failed = 0
    skipped = 0
    warnings = 0
    for result in results:
        status = result["status"]
        if status == "ok":
            ok += 1
        elif status == "failed":
            failed += 1
        else:
            skipped += 1
        if result["semantic_warning"]:
            warnings += 1

    print()
    print(
        f"Summary: ok={ok} failed={failed} skipped={skipped} semantic_warnings={warnings}"
    )
    print(f"Detailed results: {args.results_path}")
    print(f"Broker log: {args.broker_log}")


if __name__ == "__main__":
    main()



