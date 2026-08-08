#! /usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Host-side client for the KVM runner's virtio message channel.

Connects to the unix socket QEMU's `-chardev socket,server=on` listens on,
replays a JSON command sequence at the guest, prints what the TA returned, and
exits non-zero if anything -- the protocol, the runner, or the TA -- reports a
failure.

The JSON is *the same shape* `litebox_runner_optee_on_linux_userland` already
consumes, so `tests/hello-ta-cmds.json` and its siblings work unchanged. The
field names are `func_id`, `cmd_id`, `args`, `param_type`, `value_a`,
`value_b`, `data_base64` and `buffer_size`; see `TaCommandBase64` in that
crate's `src/tests.rs`, which is the definition this mirrors.

The wire format is `litebox_runner_kvm/src/proto.rs`. It is small enough to
restate here rather than generate, and restating it means this script has no
dependencies beyond the standard library -- which matters because it runs in
CI next to a QEMU and a nightly toolchain and should not also need a Python
environment.

    [u32 len][u16 version][u16 opcode][payload...]

little-endian throughout, `len` counting everything after itself.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import struct
import sys
import time

# --------------------------------------------------------------------------
# The wire format. Must agree with litebox_runner_kvm/src/proto.rs.
# --------------------------------------------------------------------------

VERSION = 1
MAX_FRAME_LEN = 1024 * 1024
MAX_PARAMS = 4

OP_OPEN_SESSION = 1
OP_INVOKE_COMMAND = 2
OP_CLOSE_SESSION = 3
OP_SHUTDOWN = 4
OP_RESPONSE = 5

OPCODE_NAMES = {
    OP_OPEN_SESSION: "OpenSession",
    OP_INVOKE_COMMAND: "InvokeCommand",
    OP_CLOSE_SESSION: "CloseSession",
    OP_SHUTDOWN: "Shutdown",
    OP_RESPONSE: "Response",
}

TAG_NONE = 0
TAG_VALUE_INPUT = 1
TAG_VALUE_OUTPUT = 2
TAG_VALUE_INOUT = 3
TAG_MEMREF_INPUT = 4
TAG_MEMREF_OUTPUT = 5
TAG_MEMREF_INOUT = 6

TAG_NAMES = {
    TAG_NONE: "none",
    TAG_VALUE_INPUT: "value_input",
    TAG_VALUE_OUTPUT: "value_output",
    TAG_VALUE_INOUT: "value_inout",
    TAG_MEMREF_INPUT: "memref_input",
    TAG_MEMREF_OUTPUT: "memref_output",
    TAG_MEMREF_INOUT: "memref_inout",
}

STATUS_OK = 0

# `func_id` strings, as the userland runner's serde `rename_all = "snake_case"`
# spells them.
FUNC_IDS = {
    "open_session": OP_OPEN_SESSION,
    "invoke_command": OP_INVOKE_COMMAND,
    "close_session": OP_CLOSE_SESSION,
}


class ProtocolError(Exception):
    """A frame that could not be decoded, or a reply that made no sense."""


class TaError(Exception):
    """The runner or the TA reported a failure."""


def _put_bytes(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def encode_param(param: dict) -> bytes:
    """Encodes one JSON argument in the wire's parameter form."""
    kind = param.get("param_type")
    if kind == "value_input":
        return struct.pack(
            "<BQQ", TAG_VALUE_INPUT, int(param["value_a"]), int(param["value_b"])
        )
    if kind == "value_output":
        # Carried even on a request, where both halves are zero. See the
        # `Param` doc comment in proto.rs for why the encoding is symmetric.
        return struct.pack("<BQQ", TAG_VALUE_OUTPUT, 0, 0)
    if kind == "value_inout":
        return struct.pack(
            "<BQQ", TAG_VALUE_INOUT, int(param["value_a"]), int(param["value_b"])
        )
    if kind == "memref_input":
        data = base64.b64decode(param["data_base64"])
        return struct.pack("<B", TAG_MEMREF_INPUT) + _put_bytes(data)
    if kind == "memref_output":
        size = int(param["buffer_size"])
        return struct.pack("<BQ", TAG_MEMREF_OUTPUT, size) + _put_bytes(b"")
    if kind == "memref_inout":
        data = base64.b64decode(param["data_base64"])
        size = int(param["buffer_size"])
        if size < len(data):
            raise ValueError(
                f"buffer_size {size} is smaller than the {len(data)} bytes of data"
            )
        return struct.pack("<BQ", TAG_MEMREF_INOUT, size) + _put_bytes(data)
    raise ValueError(f"unknown param_type {kind!r}")


def encode_request(opcode: int, cmd_id: int, params: list[dict]) -> bytes:
    """Builds a complete request frame."""
    if opcode == OP_SHUTDOWN:
        payload = b""
    else:
        if len(params) > MAX_PARAMS:
            raise ValueError(f"{len(params)} arguments, at most {MAX_PARAMS} are allowed")
        payload = struct.pack("<IB", cmd_id, len(params))
        for param in params:
            payload += encode_param(param)
    body = struct.pack("<HH", VERSION, opcode) + payload
    if len(body) + 4 > MAX_FRAME_LEN:
        raise ValueError(f"frame of {len(body) + 4} bytes exceeds the maximum")
    return struct.pack("<I", len(body)) + body


class Cursor:
    """A bounds-checked read cursor, so a short reply is an error not a crash."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ProtocolError(
                f"truncated: wanted {n} bytes, {len(self.data) - self.pos} remain"
            )
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def blob(self) -> bytes:
        return self.take(self.u32())

    def finish(self) -> None:
        if self.pos != len(self.data):
            raise ProtocolError(f"{len(self.data) - self.pos} bytes left over")


def decode_param(cur: Cursor) -> dict:
    tag = cur.u8()
    if tag == TAG_NONE:
        return {"param_type": "none"}
    if tag in (TAG_VALUE_INPUT, TAG_VALUE_OUTPUT, TAG_VALUE_INOUT):
        return {
            "param_type": TAG_NAMES[tag],
            "value_a": cur.u64(),
            "value_b": cur.u64(),
        }
    if tag == TAG_MEMREF_INPUT:
        return {"param_type": TAG_NAMES[tag], "data": cur.blob()}
    if tag in (TAG_MEMREF_OUTPUT, TAG_MEMREF_INOUT):
        return {
            "param_type": TAG_NAMES[tag],
            "buffer_size": cur.u64(),
            "data": cur.blob(),
        }
    raise ProtocolError(f"unknown parameter tag {tag}")


def decode_response(frame: bytes) -> dict:
    """Decodes a complete response frame."""
    cur = Cursor(frame)
    declared = cur.u32()
    if declared < 4:
        raise ProtocolError(f"frame declares {declared} bytes, under the header")
    if declared + 4 > MAX_FRAME_LEN:
        raise ProtocolError(f"frame declares {declared} bytes, over the maximum")
    version = cur.u16()
    if version != VERSION:
        raise ProtocolError(f"unknown protocol version {version}")
    opcode = cur.u16()
    if opcode != OP_RESPONSE:
        raise ProtocolError(f"expected a Response, got opcode {opcode}")
    status = cur.u32()
    ta_return = cur.u32()
    count = cur.u8()
    if count > MAX_PARAMS:
        raise ProtocolError(f"{count} parameters, at most {MAX_PARAMS} are allowed")
    params = [decode_param(cur) for _ in range(count)]
    message = cur.blob().decode("utf-8", errors="replace")
    cur.finish()
    return {
        "status": status,
        "ta_return": ta_return,
        "params": params,
        "message": message,
    }


# --------------------------------------------------------------------------
# The connection.
# --------------------------------------------------------------------------


def connect(path: str, timeout: float) -> socket.socket:
    """Connects to `path`, retrying until `timeout` seconds have passed.

    QEMU is the socket *server* here, so there is an unavoidable race: this
    process may reach `connect` before QEMU has created the socket, or before
    it has begun accepting. A fixed `sleep` would be a guess that is both too
    long on a fast machine and too short on a loaded one; a bounded retry is
    neither. Both `FileNotFoundError` (the path does not exist yet) and
    `ConnectionRefusedError` (it exists but nothing is listening) are retried,
    because which one occurs depends on how far QEMU has got.
    """
    deadline = time.monotonic() + timeout
    attempts = 0
    last: OSError | None = None
    while time.monotonic() < deadline:
        attempts += 1
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(path)
            print(f"[client] connected to {path} after {attempts} attempt(s)")
            return sock
        except (FileNotFoundError, ConnectionRefusedError) as error:
            last = error
            sock.close()
            time.sleep(0.05)
    raise TaError(
        f"could not connect to {path} within {timeout}s "
        f"({attempts} attempts, last error: {last})"
    )


def read_frame(sock: socket.socket) -> bytes:
    """Reads exactly one frame off the stream.

    virtio-console does not preserve message boundaries in either direction,
    so the length prefix is read first and then exactly that many more bytes.
    """
    prefix = read_exactly(sock, 4)
    (declared,) = struct.unpack("<I", prefix)
    if declared < 4:
        raise ProtocolError(f"frame declares {declared} bytes, under the header")
    if declared + 4 > MAX_FRAME_LEN:
        raise ProtocolError(f"frame declares {declared} bytes, over the maximum")
    return prefix + read_exactly(sock, declared)


def read_exactly(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ProtocolError(
                f"the guest closed the channel with {n - len(out)} bytes still owed"
            )
        out += chunk
    return out


# --------------------------------------------------------------------------
# Driving a command sequence.
# --------------------------------------------------------------------------


def describe_param(index: int, param: dict) -> str:
    kind = param["param_type"]
    if kind == "none":
        return f"    [{index}] none"
    if kind.startswith("value"):
        return (
            f"    [{index}] {kind} value_a={param['value_a']:#x} "
            f"value_b={param['value_b']:#x}"
        )
    data = param.get("data", b"")
    shown = data[:32]
    tail = "..." if len(data) > len(shown) else ""
    return (
        f"    [{index}] {kind} buffer_size={param.get('buffer_size', 0)} "
        f"len={len(data)} data={shown!r}{tail}"
    )


def exchange(sock: socket.socket, opcode: int, cmd_id: int, params: list[dict]) -> dict:
    """Sends one request and prints the reply, raising on any failure."""
    name = OPCODE_NAMES[opcode]
    detail = f" cmd_id={cmd_id}" if opcode == OP_INVOKE_COMMAND else ""
    print(f"[client] -> {name}{detail} with {len(params)} argument(s)")
    sock.sendall(encode_request(opcode, cmd_id, params))

    response = decode_response(read_frame(sock))
    print(
        f"[client] <- status={response['status']} "
        f"ta_return={response['ta_return']:#010x}"
    )
    for index, param in enumerate(response["params"]):
        if param["param_type"] != "none":
            print(describe_param(index, param))
    if response["message"]:
        print(f"    message: {response['message']}")

    if response["status"] != STATUS_OK:
        raise TaError(f"{name} failed: {response['message']}")
    if response["ta_return"] != 0:
        raise TaError(f"{name}: the TA returned {response['ta_return']:#010x}")
    return response


def run(path: str, commands: list[dict], timeout: float, shutdown: bool) -> None:
    sock = connect(path, timeout)
    try:
        for command in commands:
            raw = command.get("func_id")
            if raw not in FUNC_IDS:
                raise TaError(f"unknown func_id {raw!r}")
            args = command.get("args", [])
            exchange(sock, FUNC_IDS[raw], int(command.get("cmd_id", 0)), args)
        if shutdown:
            exchange(sock, OP_SHUTDOWN, 0, [])
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket", help="path of the unix socket QEMU is listening on")
    parser.add_argument(
        "commands",
        help="JSON command sequence, in the shape "
        "litebox_runner_optee_on_linux_userland already consumes",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=60.0,
        help="seconds to keep retrying the connection (default: 60)",
    )
    parser.add_argument(
        "--no-shutdown",
        action="store_true",
        help="do not send a Shutdown after the sequence, leaving the guest running",
    )
    args = parser.parse_args()

    with open(args.commands, "r", encoding="utf-8") as handle:
        commands = json.load(handle)
    if not isinstance(commands, list):
        print(f"[client] {args.commands} is not a JSON array", file=sys.stderr)
        return 2

    try:
        run(args.socket, commands, args.timeout, not args.no_shutdown)
    except (ProtocolError, TaError, ValueError, OSError) as error:
        # Non-zero, and specific. A client that always exited 0 would make the
        # integration test that runs it worthless.
        print(f"[client] FAILED: {error}", file=sys.stderr)
        return 1
    print("[client] sequence completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
