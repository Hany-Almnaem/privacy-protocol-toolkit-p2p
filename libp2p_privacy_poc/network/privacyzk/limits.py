"""Stream framing helpers with size limits and timeouts."""

from __future__ import annotations

import struct
from typing import Any

import trio

from .errors import SchemaError, SizeLimitError

MAX_FRAME_BYTES = 131072
READ_TIMEOUT = 5.0
WRITE_TIMEOUT = 5.0


async def read_exact(stream: Any, size: int, timeout: float) -> bytes:
    if size < 0:
        raise SchemaError("invalid read size")
    data = bytearray()
    with trio.fail_after(timeout):
        while len(data) < size:
            chunk = await stream.read(size - len(data))
            if not chunk:
                raise SchemaError("unexpected EOF")
            data.extend(chunk)
    return bytes(data)


async def read_frame(
    stream: Any, max_bytes: int = MAX_FRAME_BYTES, timeout: float = READ_TIMEOUT
) -> bytes:
    header = await read_exact(stream, 4, timeout)
    length = struct.unpack(">I", header)[0]
    if length > max_bytes:
        raise SizeLimitError("frame too large")
    return await read_exact(stream, length, timeout)


async def write_frame(
    stream: Any,
    payload: bytes,
    max_bytes: int = MAX_FRAME_BYTES,
    timeout: float = WRITE_TIMEOUT,
) -> None:
    if len(payload) > max_bytes:
        raise SizeLimitError("frame too large")
    header = struct.pack(">I", len(payload))
    with trio.fail_after(timeout):
        await stream.write(header + payload)
