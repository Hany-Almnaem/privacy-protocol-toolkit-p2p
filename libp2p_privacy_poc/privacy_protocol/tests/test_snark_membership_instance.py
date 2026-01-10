"""Tests for SNARK membership instance helpers."""

from __future__ import annotations

from pathlib import Path
import os

import pytest

membership_py = pytest.importorskip("membership_py")

from privacy_protocol.snark.membership import (  # noqa: E402
    build_membership_instance_bytes,
    write_membership_instance_files,
)


def test_build_membership_instance_bytes() -> None:
    instance_bytes, public_inputs_bytes = build_membership_instance_bytes(
        identity_scalar=1,
        blinding=2,
        merkle_path=[(b"\x01" * 32, False)],
        schema_version=1,
    )

    assert isinstance(instance_bytes, (bytes, bytearray))
    assert isinstance(public_inputs_bytes, (bytes, bytearray))
    assert instance_bytes
    assert public_inputs_bytes


def test_write_membership_instance_files(tmp_path: Path) -> None:
    instance_path = tmp_path / "instance.bin"
    public_inputs_path = tmp_path / "public_inputs.bin"

    write_membership_instance_files(
        identity_scalar=1,
        blinding=2,
        merkle_path=[(b"\x02" * 32, False)],
        instance_path=instance_path,
        public_inputs_path=public_inputs_path,
        schema_version=1,
    )

    assert instance_path.exists()
    assert public_inputs_path.exists()


def test_membership_verify_e2e_if_available() -> None:
    if os.environ.get("SNARK_MEMBERSHIP_E2E") != "1":
        pytest.skip("SNARK_MEMBERSHIP_E2E not enabled")

    repo_root = Path(__file__).resolve().parents[3]
    fixtures_dir = repo_root / "privacy_circuits/fixtures/membership"
    vk = repo_root / "privacy_circuits/params/membership_depth16_vk.bin"
    public_inputs = fixtures_dir / "depth16_public_inputs.bin"
    proof = fixtures_dir / "depth16_proof.bin"

    if not (vk.exists() and public_inputs.exists() and proof.exists()):
        pytest.skip("SNARK params/proof not available")

    assert membership_py.verify_membership_v1(
        str(vk),
        str(public_inputs),
        str(proof),
    )
