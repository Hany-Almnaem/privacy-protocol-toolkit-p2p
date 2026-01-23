"""Unit tests for proof providers."""

from __future__ import annotations

from pathlib import Path

import cbor2
import pytest

from libp2p_privacy_poc.network.privacyzk.constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MAX_PROOF_BYTES,
    MAX_PUBLIC_INPUTS_BYTES,
    MSG_V,
    SNARK_SCHEMA_V,
)
from libp2p_privacy_poc.network.privacyzk.messages import ProofRequest
from libp2p_privacy_poc.network.privacyzk.provider import (
    FixtureProofProvider,
    HybridProofProvider,
    ProviderConfig,
    RealProofProvider,
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


def test_fixture_provider_happy_path_membership(tmp_path: Path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    _write_fixture(base, "membership_vk.bin", b"vk")
    _write_fixture(base, "public_inputs.bin", b"pi")
    _write_fixture(base, "membership_proof.bin", b"proof")

    config = ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path))
    provider = FixtureProofProvider(config)
    resp = provider.get_proof(_membership_req())

    assert resp.ok is True
    meta = cbor2.loads(resp.meta)
    assert meta["prove_mode"] == "fixture"
    assert meta["statement"] == "membership"


def test_fixture_provider_missing_files_returns_ok_false(tmp_path: Path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    _write_fixture(base, "membership_vk.bin", b"vk")
    _write_fixture(base, "public_inputs.bin", b"pi")

    config = ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path))
    provider = FixtureProofProvider(config)
    resp = provider.get_proof(_membership_req())

    assert resp.ok is False
    assert resp.err


def test_fixture_provider_rejects_oversized_public_inputs(tmp_path: Path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    _write_fixture(base, "membership_vk.bin", b"vk")
    _write_fixture(base, "public_inputs.bin", b"p" * (MAX_PUBLIC_INPUTS_BYTES + 1))
    _write_fixture(base, "membership_proof.bin", b"proof")

    config = ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path))
    provider = FixtureProofProvider(config)
    resp = provider.get_proof(_membership_req())

    assert resp.ok is False
    assert "public_inputs" in resp.err


def test_real_provider_without_callback_returns_ok_false() -> None:
    config = ProviderConfig(prove_mode="real")
    provider = RealProofProvider(config)

    resp = provider.get_proof(_membership_req())
    assert resp.ok is False
    assert resp.err == "real proving not available"


def test_real_provider_with_callback_enforces_size_limits() -> None:
    def prover(_: ProofRequest) -> tuple[bytes, bytes, dict]:
        return b"pi", b"p" * (MAX_PROOF_BYTES + 1), {}

    config = ProviderConfig(prove_mode="real")
    provider = RealProofProvider(config, prover=prover)

    resp = provider.get_proof(_membership_req())
    assert resp.ok is False
    assert "proof" in resp.err


def test_hybrid_provider_prefers_real_when_available(tmp_path: Path) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    _write_fixture(base, "membership_vk.bin", b"vk")
    _write_fixture(base, "public_inputs.bin", b"pi")
    _write_fixture(base, "membership_proof.bin", b"proof")

    def prover(_: ProofRequest) -> tuple[bytes, bytes, dict]:
        return b"real_pi", b"real_proof", {}

    config = ProviderConfig(prove_mode="prefer-real", base_dir=str(tmp_path))
    fixture = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    real = RealProofProvider(ProviderConfig(prove_mode="real"), prover=prover)
    provider = HybridProofProvider(config, fixture_provider=fixture, real_provider=real)

    resp = provider.get_proof(_membership_req())
    meta = cbor2.loads(resp.meta)
    assert resp.ok is True
    assert meta["prove_mode"] == "real"


def test_hybrid_provider_falls_back_to_fixture_with_explicit_meta(
    tmp_path: Path,
) -> None:
    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    _write_fixture(base, "membership_vk.bin", b"vk")
    _write_fixture(base, "public_inputs.bin", b"pi")
    _write_fixture(base, "membership_proof.bin", b"proof")

    config = ProviderConfig(prove_mode="prefer-real", base_dir=str(tmp_path))
    fixture = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    real = RealProofProvider(ProviderConfig(prove_mode="real"))
    provider = HybridProofProvider(config, fixture_provider=fixture, real_provider=real)

    resp = provider.get_proof(_membership_req())
    meta = cbor2.loads(resp.meta)
    assert resp.ok is True
    assert meta["prove_mode"] == "fixture"
    assert meta["fallback_from"] == "real"


def test_hybrid_provider_returns_error_if_both_fail(tmp_path: Path) -> None:
    config = ProviderConfig(prove_mode="prefer-real", base_dir=str(tmp_path))
    fixture = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    real = RealProofProvider(ProviderConfig(prove_mode="real"))
    provider = HybridProofProvider(config, fixture_provider=fixture, real_provider=real)

    resp = provider.get_proof(_membership_req())
    assert resp.ok is False
    assert resp.err == "real and fixture failed"
