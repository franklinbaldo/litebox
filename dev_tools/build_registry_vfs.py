#!/usr/bin/env python3
"""Export host Windows registry subtrees into VFS-structured files for litebox.

Creates a directory tree under `__registry/` where:
  - Registry keys map to directories
  - Registry values map to files under `__values/` subdirectories
  - Each value file has a 4-byte LE type prefix followed by raw data

Value encoding (little-endian):
  bytes 0..4: REG type (REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3, REG_DWORD=4, ...)
  bytes 4..:  raw data (UTF-16LE for REG_SZ/REG_EXPAND_SZ, LE u32 for REG_DWORD, etc.)

Path mapping:
  \\Registry\\Machine\\System\\... -> __registry/machine/system/...
  \\Registry\\User\\...            -> __registry/user/...

Usage:
    python build_registry_vfs.py --output-dir /tmp/reg_vfs
    python build_registry_vfs.py --tar windows_dlls.tar   # append to existing tar
"""

import argparse
import io
import os
import struct
import sys
import tarfile

# winreg is only available on Windows
try:
    import winreg
except ImportError:
    winreg = None

# Registry type constants matching Windows REG_* values.
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7

# Registry subtrees to export.
# Each entry is (hive_constant, subkey_path, recursive).
REGISTRY_SUBTREES = [
    # Winsock2 parameters and catalogs (needed for WSAStartup)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters",
     True),
    # Crypto providers (needed for bcrypt/rsaenh)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Cryptography\Defaults\Provider",
     True),
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Cryptography\Defaults\Provider Types",
     True),
    # Winsock 1.x transport registry (needed by mswsock.dll WSPSocket)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SYSTEM\CurrentControlSet\Services\Winsock\Parameters",
     False),
    # TCP/IP Winsock helper (maps AF_INET to wshtcpip.dll)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock",
     False),
    # Winsock setup migration providers (maps Winsock 1.x transport names to
    # Winsock 2.0 provider GUIDs; needed by mswsock.dll WSPSocket)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SYSTEM\CurrentControlSet\Services\Winsock\Setup Migration\Providers",
     True),
    # NLS / code page info
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SYSTEM\CurrentControlSet\Control\Nls\CodePage",
     False),
    # Control Panel\International (locale settings)
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"Control Panel\International",
     False),
    # MUI language settings (used by ntdll MUI resource loading)
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"Control Panel\Desktop\MuiCached",
     False),
]

# Mapping from hive constants to VFS path prefixes.
HIVE_PREFIX = {}
if winreg:
    HIVE_PREFIX = {
        winreg.HKEY_LOCAL_MACHINE: "__registry/machine",
        winreg.HKEY_CURRENT_USER: "__registry/user/.default",
        winreg.HKEY_USERS: "__registry/user",
    }


def encode_value(val, reg_type):
    """Encode a registry value into the VFS file format: 4-byte LE type + raw data."""
    header = struct.pack("<I", reg_type)
    if reg_type in (REG_SZ, REG_EXPAND_SZ):
        if isinstance(val, str):
            data = val.encode("utf-16-le") + b"\x00\x00"
        elif isinstance(val, bytes):
            data = val
        else:
            data = str(val).encode("utf-16-le") + b"\x00\x00"
    elif reg_type == REG_DWORD:
        data = struct.pack("<I", val if val is not None else 0)
    elif reg_type == REG_BINARY:
        data = val if isinstance(val, bytes) else b""
    elif reg_type == REG_MULTI_SZ:
        if isinstance(val, (list, tuple)):
            data = b""
            for s in val:
                data += s.encode("utf-16-le") + b"\x00\x00"
            data += b"\x00\x00"
        elif isinstance(val, bytes):
            data = val
        else:
            data = b"\x00\x00"
    else:
        # Unknown type: store raw bytes if available
        data = val if isinstance(val, bytes) else b""
    return header + data


def export_key(hive, subkey_path, recursive, collected):
    """Export a registry key and its values to the collected dict.

    collected: dict mapping VFS path -> bytes (file content)
    """
    hive_prefix = HIVE_PREFIX.get(hive, "__registry/unknown")
    vfs_dir = f"{hive_prefix}/{subkey_path.lower().replace(chr(92), '/')}"

    try:
        key = winreg.OpenKey(hive, subkey_path)
    except OSError:
        print(f"  SKIP (not found): {subkey_path}", file=sys.stderr)
        return

    # Export values
    i = 0
    while True:
        try:
            name, val, reg_type = winreg.EnumValue(key, i)
            if name == "":
                vfs_name = "__default"
            else:
                vfs_name = name.lower()
            vfs_path = f"{vfs_dir}/__values/{vfs_name}"
            collected[vfs_path] = encode_value(val, reg_type)
            i += 1
        except OSError:
            break

    # Recurse into subkeys
    if recursive:
        j = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, j)
                child_path = f"{subkey_path}\\{subkey_name}"
                export_key(hive, child_path, True, collected)
                j += 1
            except OSError:
                break

    winreg.CloseKey(key)


def build_registry_files():
    """Export all configured registry subtrees and return dict of VFS path -> bytes."""
    if winreg is None:
        print("ERROR: winreg not available (not running on Windows)", file=sys.stderr)
        sys.exit(1)

    collected = {}
    for hive, subkey, recursive in REGISTRY_SUBTREES:
        print(f"  Exporting: {subkey} (recursive={recursive})")
        export_key(hive, subkey, recursive, collected)

    return collected


def add_to_tar(tar, collected):
    """Add collected registry files to a tar archive.

    Only value files are added; the tar_ro VFS auto-creates intermediate
    directories from file paths, so explicit DIRTYPE entries are not needed
    (and would conflict with the directory inference logic).
    """
    for vfs_path, data in sorted(collected.items()):
        info = tarfile.TarInfo(vfs_path)
        info.size = len(data)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(
        description="Export Windows registry to VFS files for litebox"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--output-dir", help="Write registry VFS files to this directory"
    )
    group.add_argument(
        "--tar", help="Append registry VFS files to this tar archive"
    )
    args = parser.parse_args()

    print("Building registry VFS...")
    collected = build_registry_files()
    print(f"  Collected {len(collected)} registry values")

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        for vfs_path, data in sorted(collected.items()):
            full_path = os.path.join(args.output_dir, vfs_path.replace("/", os.sep))
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "wb") as f:
                f.write(data)
            print(f"  {vfs_path} ({len(data)} bytes)")
        print(f"\nWrote {len(collected)} files to {args.output_dir}")
    else:
        with tarfile.open(args.tar, "a", format=tarfile.USTAR_FORMAT) as tar:
            add_to_tar(tar, collected)
        print(f"\nAppended {len(collected)} registry entries to {args.tar}")


if __name__ == "__main__":
    main()
