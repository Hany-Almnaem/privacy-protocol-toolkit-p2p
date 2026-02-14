"""Unit tests for request handler."""

from __future__ import annotations

from pathlib import Path

import cbor2
import pytest

from libp2p_privacy_poc.network.privacyzk.constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MAX_META_BYTES,
    MSG_V,
    SNARK_SCHEMA_V,
)
from libp2p_privacy_poc.network.privacyzk.handler import handle_proof_request_bytes
from libp2p_privacy_poc.network.privacyzk.messages import (
    ProofRequest,
    decode_response,
    encode_request,
)
from libp2p_privacy_poc.network.privacyzk.provider import (
    FixtureProofProvider,
    ProviderConfig,
    ProofProvider,
)


def _write_fixture(path: Path, name: str, payload: bytes) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / name).write_bytes(payload)


def _membership_req() -> ProofRequest:
    return ProofRequest(
        msg_v=MSG_V,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=b"n" * 16,
    )


def test_handler_returns_fixture_response_ok_true(tmp_path: Path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    _write_fixture(base, "membership_vk.bin", b"vk")
    _write_fixture(base, "public_inputs.bin", b"pi")
    _write_fixture(base, "membership_proof.bin", b"proof")

    provider = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    request_blob = encode_request(_membership_req())
    response_blob = handle_proof_request_bytes(request_blob, provider)
    decoded = decode_response(response_blob)

    assert decoded.ok is True
    assert decoded.public_inputs == b"pi"
    assert decoded.proof == b"proof"


def test_handler_returns_ok_false_on_bad_request_blob() -> None:
    response_blob = handle_proof_request_bytes(b"not-cbor", provider=_DummyProvider())
    decoded = decode_response(response_blob)
    assert decoded.ok is False
    assert decoded.err


def test_handler_returns_ok_false_if_provider_raises() -> None:
    request_blob = encode_request(_membership_req())
    response_blob = handle_proof_request_bytes(request_blob, provider=_FailProvider())
    decoded = decode_response(response_blob)
    assert decoded.ok is False
    assert decoded.err == "provider error"


def test_handler_meta_is_bytes_and_small(tmp_path: Path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    _write_fixture(base, "membership_vk.bin", b"vk")
    _write_fixture(base, "public_inputs.bin", b"pi")
    _write_fixture(base, "membership_proof.bin", b"proof")

    provider = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    response_blob = handle_proof_request_bytes(encode_request(_membership_req()), provider)
    decoded = decode_response(response_blob)
    assert isinstance(decoded.meta, bytes)
    assert len(decoded.meta) <= MAX_META_BYTES
    meta = cbor2.loads(decoded.meta)
    assert meta["prove_mode"] == "fixture"


class _FailProvider:
    def get_proof(self, req: ProofRequest):
        raise RuntimeError("boom")


class _DummyProvider:
    def get_proof(self, req: ProofRequest):
        return _FailProvider.get_proof(self, req)
