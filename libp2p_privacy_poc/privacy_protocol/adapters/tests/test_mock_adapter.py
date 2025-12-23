from __future__ import annotations

import hashlib

import pytest

from libp2p_privacy_poc.mock_zk_proofs import (
    MockZKProof,
    ZKProofType as LegacyZKProofType,
)
from libp2p_privacy_poc.privacy_protocol import factory
from libp2p_privacy_poc.privacy_protocol.feature_flags import set_backend_type
from libp2p_privacy_poc.privacy_protocol.types import ProofContext, ZKProofType

from ..mock_adapter import MockZKProofSystemAdapter


@pytest.fixture(autouse=True)
def reset_feature_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    set_backend_type(None)
    monkeypatch.delenv("PRIVACY_PROTOCOL_BACKEND", raising=False)
    yield
    set_backend_type(None)
    monkeypatch.delenv("PRIVACY_PROTOCOL_BACKEND", raising=False)


def _make_context() -> ProofContext:
    return ProofContext(peer_id="peer-1", session_id="session-1")


def test_generate_anonymity_set_proof_returns_zkproof() -> None:
    adapter = MockZKProofSystemAdapter()
    ctx = _make_context()
    proof = adapter.generate_anonymity_set_proof(ctx, anonymity_set_size=5)

    assert proof.proof_type == ZKProofType.ANONYMITY_SET_MEMBERSHIP.value
    assert isinstance(proof.commitment, bytes)
    assert len(proof.commitment) == 32
    assert proof.public_inputs["adapter"] == "mock"
    assert proof.public_inputs["v"] == 1
    assert adapter.verify_proof(proof) is True


def test_generate_proof_uses_public_inputs() -> None:
    adapter = MockZKProofSystemAdapter()
    ctx = _make_context()
    proof = adapter.generate_proof(
        ctx, witness={}, public_inputs={"anonymity_set_size": 3}
    )

    assert proof.proof_type == ZKProofType.ANONYMITY_SET_MEMBERSHIP.value
    assert adapter.verify_proof(proof) is True


def test_verify_proof_rejects_invalid_proof_type() -> None:
    adapter = MockZKProofSystemAdapter()
    ctx = _make_context()
    proof = adapter.generate_anonymity_set_proof(ctx, anonymity_set_size=3)
    proof.proof_type = "range_proof"

    assert adapter.verify_proof(proof) is False


def test_verify_proof_rejects_non_bytes_commitment() -> None:
    adapter = MockZKProofSystemAdapter()
    ctx = _make_context()
    proof = adapter.generate_anonymity_set_proof(ctx, anonymity_set_size=3)
    proof.commitment = "not-bytes"

    assert adapter.verify_proof(proof) is False


def test_verify_proof_rejects_wrong_commitment_length() -> None:
    adapter = MockZKProofSystemAdapter()
    ctx = _make_context()
    proof = adapter.generate_anonymity_set_proof(ctx, anonymity_set_size=3)
    proof.commitment = b"123"

    assert adapter.verify_proof(proof) is False


def test_verify_proof_rejects_missing_public_inputs_keys() -> None:
    adapter = MockZKProofSystemAdapter()
    ctx = _make_context()
    proof = adapter.generate_anonymity_set_proof(ctx, anonymity_set_size=3)
    proof.public_inputs.pop("adapter", None)

    assert adapter.verify_proof(proof) is False


def test_commitment_determinism_from_mock_hash() -> None:
    adapter = MockZKProofSystemAdapter()
    mock_hash = "stable-hash"
    mock_1 = MockZKProof(
        proof_type=LegacyZKProofType.ANONYMITY_SET_MEMBERSHIP,
        claim="test",
        timestamp=1234567890.0,
        public_inputs={"anonymity_set_size": 5},
        mock_proof_hash=mock_hash,
        mock_verification_key="vk",
    )
    mock_2 = MockZKProof(
        proof_type=LegacyZKProofType.ANONYMITY_SET_MEMBERSHIP,
        claim="test-2",
        timestamp=1234567891.0,
        public_inputs={"anonymity_set_size": 5},
        mock_proof_hash=mock_hash,
        mock_verification_key="vk",
    )

    proof_1 = adapter._convert_mock_proof(mock_1)
    proof_2 = adapter._convert_mock_proof(mock_2)
    expected = hashlib.sha256(mock_hash.encode("utf-8")).digest()

    assert proof_1.commitment == expected
    assert proof_1.commitment == proof_2.commitment


def test_batch_verify_behavior() -> None:
    adapter = MockZKProofSystemAdapter()
    ctx = _make_context()
    proof_1 = adapter.generate_anonymity_set_proof(ctx, anonymity_set_size=2)
    proof_2 = adapter.generate_anonymity_set_proof(ctx, anonymity_set_size=3)

    assert adapter.batch_verify([]) is True
    assert adapter.batch_verify([proof_1, proof_2]) is True

    proof_2.commitment = b"bad"
    assert adapter.batch_verify([proof_1, proof_2]) is False


def test_factory_selects_mock_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "mock")
    backend = factory.get_zk_backend()

    assert isinstance(backend, MockZKProofSystemAdapter)
    proof = backend.generate_anonymity_set_proof(
        _make_context(), anonymity_set_size=2
    )
    assert backend.verify_proof(proof) is True
