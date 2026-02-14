"""Tests for unified SNARK verification backend."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pytest

from privacy_protocol.snark.assets import resolve_fixture_paths, resolve_vk
from privacy_protocol.snark.backend import SnarkBackend


def test_backend_verifies_membership_fixtures() -> None:
    verified_any = False
    for depth in (16, 20, 24):
        resolved = _resolve_fixture("membership", 1, depth=depth)
        if resolved is None:
            continue
        vk_path, public_inputs_path, proof_path = resolved
        assert _verify_or_skip(
            "membership",
            1,
            vk_path,
            public_inputs_path,
            proof_path,
        )
        assert _verify_or_skip(
            "membership",
            1,
            Path(vk_path).read_bytes(),
            Path(public_inputs_path).read_bytes(),
            Path(proof_path).read_bytes(),
        )
        verified_any = True
    if not verified_any:
        pytest.skip("membership fixtures not available")


def test_backend_verifies_continuity_fixture_if_present() -> None:
    resolved = _resolve_fixture("continuity", 1)
    if resolved is None:
        pytest.skip("continuity fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    assert _verify_or_skip(
        "continuity",
        1,
        vk_path,
        public_inputs_path,
        proof_path,
    )
    assert _verify_or_skip(
        "continuity",
        1,
        Path(vk_path).read_bytes(),
        Path(public_inputs_path).read_bytes(),
        Path(proof_path).read_bytes(),
    )


def test_backend_verifies_unlinkability_fixture_if_present() -> None:
    resolved = _resolve_fixture("unlinkability", 2)
    if resolved is None:
        pytest.skip("unlinkability fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    assert _verify_or_skip(
        "unlinkability",
        2,
        vk_path,
        public_inputs_path,
        proof_path,
    )
    assert _verify_or_skip(
        "unlinkability",
        2,
        Path(vk_path).read_bytes(),
        Path(public_inputs_path).read_bytes(),
        Path(proof_path).read_bytes(),
    )


def test_backend_rejects_unknown_statement_type() -> None:
    with pytest.raises(ValueError, match="Unknown statement_type"):
        SnarkBackend.verify(
            "range",
            1,
            "missing_vk.bin",
            "missing_public_inputs.bin",
            "missing_proof.bin",
        )


def test_backend_rejects_wrong_schema_version() -> None:
    with pytest.raises(ValueError, match="Unsupported schema_version"):
        SnarkBackend.verify(
            "membership",
            99,
            "missing_vk.bin",
            "missing_public_inputs.bin",
            "missing_proof.bin",
        )


def test_backend_rejects_mismatched_statement_type() -> None:
    with pytest.raises(ValueError, match="Unsupported schema_version"):
        SnarkBackend.verify(
            "unlinkability",
            1,
            "missing_vk.bin",
            "missing_public_inputs.bin",
            "missing_proof.bin",
        )


def test_backend_rejects_tampered_proof() -> None:
    resolved = _resolve_fixture("membership", 1, depth=16)
    if resolved is None:
        pytest.skip("membership fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    proof_bytes = Path(proof_path).read_bytes()
    tampered = _tamper_bytes(proof_bytes)
    assert not _verify_or_skip(
        "membership",
        1,
        Path(vk_path).read_bytes(),
        Path(public_inputs_path).read_bytes(),
        tampered,
    )


def test_backend_rejects_tampered_public_inputs() -> None:
    resolved = _resolve_fixture("membership", 1, depth=16)
    if resolved is None:
        pytest.skip("membership fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    public_inputs_bytes = Path(public_inputs_path).read_bytes()
    tampered = _tamper_bytes(public_inputs_bytes)
    assert not _verify_or_skip(
        "membership",
        1,
        Path(vk_path).read_bytes(),
        tampered,
        Path(proof_path).read_bytes(),
    )


def _resolve_fixture(
    statement: str,
    schema_version: int,
    *,
    depth: int | None = None,
) -> tuple[str, str, str] | None:
    try:
        instance_path, public_inputs_path, proof_path = resolve_fixture_paths(
            statement,
            schema_version,
            depth=depth,
        )
        vk_path = resolve_vk(statement, schema_version, depth=depth)
    except FileNotFoundError:
        return None
    return str(vk_path), str(public_inputs_path), str(proof_path)


def _verify_or_skip(
    statement: str,
    schema_version: int,
    vk: str | bytes,
    public_inputs: str | bytes,
    proof: str | bytes,
) -> bool:
    try:
        return SnarkBackend.verify(
            statement,
            schema_version,
            vk,
            public_inputs,
            proof,
        )
    except ValueError as exc:
        if "Missing binding" in str(exc):
            pytest.skip(f"{statement} binding not available")
        raise


def _tamper_bytes(data: bytes) -> bytes:
    if not data:
        return data
    tampered = bytearray(data)
    index = len(tampered) - 1
    tampered[index] ^= 0x01
    return bytes(tampered)
