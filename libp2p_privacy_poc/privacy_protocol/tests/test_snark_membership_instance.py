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
from privacy_protocol.snark.assets import resolve_fixture_paths, resolve_vk  # noqa: E402


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

    try:
        vk = resolve_vk("membership", 1, depth=16)
        _instance, public_inputs, proof = resolve_fixture_paths(
            "membership",
            1,
            depth=16,
        )
    except FileNotFoundError:
        pytest.skip("SNARK membership fixtures not available")

    assert membership_py.verify_membership_v1(
        str(vk),
        str(public_inputs),
        str(proof),
    )
