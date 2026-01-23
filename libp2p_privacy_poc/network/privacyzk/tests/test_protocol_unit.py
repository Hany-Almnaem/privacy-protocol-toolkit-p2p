"""Unit tests for privacyzk protocol framing."""

from __future__ import annotations

import struct

import pytest
import trio

from libp2p_privacy_poc.network.privacyzk.constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MSG_V,
    SNARK_SCHEMA_V,
)
from libp2p_privacy_poc.network.privacyzk.handler import handle_proof_request_bytes
from libp2p_privacy_poc.network.privacyzk.limits import MAX_FRAME_BYTES, read_frame
from libp2p_privacy_poc.network.privacyzk.messages import (
    ProofRequest,
    decode_response,
    encode_request,
)
from libp2p_privacy_poc.network.privacyzk.protocol import handle_proof_stream
from libp2p_privacy_poc.network.privacyzk.provider import (
    FixtureProofProvider,
    ProviderConfig,
)


class FakeStream:
    def __init__(self, read_buffer: bytes = b"") -> None:
        self._read_buffer = bytearray(read_buffer)
        self._write_buffer = bytearray()
        self.closed = False

    async def read(self, n: int | None = None) -> bytes:
        if n is None:
            n = len(self._read_buffer)
        if n <= 0:
            return b""
        if not self._read_buffer:
            return b""
        chunk = self._read_buffer[:n]
        del self._read_buffer[:n]
        return bytes(chunk)

    async def write(self, data: bytes) -> None:
        self._write_buffer.extend(data)

    async def close(self) -> None:
        self.closed = True

    def get_written(self) -> bytes:
        return bytes(self._write_buffer)


def _membership_req() -> ProofRequest:
    return ProofRequest(
        msg_v=MSG_V,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=b"n" * 16,
    )


@pytest.mark.trio
async def test_handler_reads_and_writes_frame(tmp_path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    base.mkdir(parents=True, exist_ok=True)
    (base / "membership_vk.bin").write_bytes(b"vk")
    (base / "public_inputs.bin").write_bytes(b"pi")
    (base / "membership_proof.bin").write_bytes(b"proof")

    provider = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    request_blob = encode_request(_membership_req())
    frame = struct.pack(">I", len(request_blob)) + request_blob
    stream = FakeStream(frame)

    await handle_proof_stream(stream, provider)
    written = stream.get_written()
    assert written
    length = struct.unpack(">I", written[:4])[0]
    payload = written[4 : 4 + length]
    response = decode_response(payload)
    assert response.ok is True


@pytest.mark.trio
async def test_handler_rejects_oversized_frame() -> None:
    oversized = struct.pack(">I", MAX_FRAME_BYTES + 1)
    stream = FakeStream(oversized)
    provider = FixtureProofProvider(ProviderConfig(prove_mode="fixture"))

    await handle_proof_stream(stream, provider)
    written = stream.get_written()
    assert written
    length = struct.unpack(">I", written[:4])[0]
    response = decode_response(written[4 : 4 + length])
    assert response.ok is False


@pytest.mark.trio
async def test_handler_malformed_request_returns_ok_false(tmp_path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    base.mkdir(parents=True, exist_ok=True)
    (base / "membership_vk.bin").write_bytes(b"vk")
    (base / "public_inputs.bin").write_bytes(b"pi")
    (base / "membership_proof.bin").write_bytes(b"proof")

    provider = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    payload = b"not-cbor"
    frame = struct.pack(">I", len(payload)) + payload
    stream = FakeStream(frame)

    await handle_proof_stream(stream, provider)
    written = stream.get_written()
    length = struct.unpack(">I", written[:4])[0]
    response = decode_response(written[4 : 4 + length])
    assert response.ok is False
