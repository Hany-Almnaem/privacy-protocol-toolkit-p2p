"""Tests for unified SNARK verification backend."""

from __future__ import annotations

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
        assert SnarkBackend.verify(
            "membership",
            1,
            vk_path,
            public_inputs_path,
            proof_path,
        )
        verified_any = True
    if not verified_any:
        pytest.skip("membership fixtures not available")


def test_backend_verifies_continuity_fixture_if_present() -> None:
    resolved = _resolve_fixture("continuity", 1)
    if resolved is None:
        pytest.skip("continuity fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    assert SnarkBackend.verify(
        "continuity",
        1,
        vk_path,
        public_inputs_path,
        proof_path,
    )


def test_backend_verifies_unlinkability_fixture_if_present() -> None:
    resolved = _resolve_fixture("unlinkability", 2)
    if resolved is None:
        pytest.skip("unlinkability fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    assert SnarkBackend.verify(
        "unlinkability",
        2,
        vk_path,
        public_inputs_path,
        proof_path,
    )


def test_backend_rejects_unknown_statement_type() -> None:
    assert not SnarkBackend.verify(
        "range",
        1,
        "missing_vk.bin",
        "missing_public_inputs.bin",
        "missing_proof.bin",
    )


def test_backend_rejects_wrong_schema_version() -> None:
    resolved = _resolve_fixture("membership", 1, depth=16)
    if resolved is None:
        pytest.skip("membership fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    assert not SnarkBackend.verify(
        "membership",
        2,
        vk_path,
        public_inputs_path,
        proof_path,
    )


def test_backend_rejects_mismatched_statement_type() -> None:
    resolved = _resolve_fixture("membership", 1, depth=16)
    if resolved is None:
        pytest.skip("membership fixtures not available")
    vk_path, public_inputs_path, proof_path = resolved
    assert not SnarkBackend.verify(
        "continuity",
        1,
        vk_path,
        public_inputs_path,
        proof_path,
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
