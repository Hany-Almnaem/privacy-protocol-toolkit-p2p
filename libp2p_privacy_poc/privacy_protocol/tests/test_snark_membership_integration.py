"""Integration tests for SNARK membership verification via Python bindings."""

from __future__ import annotations

from pathlib import Path
import hashlib
import subprocess

import pytest

membership_py = pytest.importorskip("membership_py")

from privacy_protocol.snark.membership import (  # noqa: E402
    build_membership_instance_bytes,
    write_membership_instance_files,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = REPO_ROOT / "privacy_circuits/fixtures/membership"
PARAMS_DIR = REPO_ROOT / "privacy_circuits/params"
VERIFY_BIN = REPO_ROOT / "privacy_circuits/target/debug/verify_membership"
SNARK_DEPTH = 16


def test_membership_instance_matches_fixture() -> None:
    merkle_path = _fixture_merkle_path(SNARK_DEPTH)
    instance_bytes, public_inputs_bytes = build_membership_instance_bytes(
        identity_scalar=1,
        blinding=2,
        merkle_path=merkle_path,
        depth=SNARK_DEPTH,
        schema_version=1,
    )

    instance_path = FIXTURES_DIR / "depth16_instance.bin"
    public_inputs_path = FIXTURES_DIR / "depth16_public_inputs.bin"

    assert instance_path.exists(), "missing membership instance fixture"
    assert public_inputs_path.exists(), "missing membership public inputs fixture"

    assert instance_bytes == instance_path.read_bytes()
    assert public_inputs_bytes == public_inputs_path.read_bytes()


def test_membership_proof_verifies_with_fixture() -> None:
    vk_path = PARAMS_DIR / "membership_depth16_vk.bin"
    public_inputs_path = FIXTURES_DIR / "depth16_public_inputs.bin"
    proof_path = FIXTURES_DIR / "depth16_proof.bin"

    assert vk_path.exists(), "missing membership verifying key"
    assert public_inputs_path.exists(), "missing membership public inputs fixture"
    assert proof_path.exists(), "missing membership proof fixture"

    assert membership_py.verify_membership_v1(
        str(vk_path),
        str(public_inputs_path),
        str(proof_path),
    )


@pytest.mark.slow
def test_membership_v1_instance_verifies_rust_and_pyo3(tmp_path: Path) -> None:
    if not VERIFY_BIN.exists():
        pytest.skip("verify_membership binary missing; build privacy_circuits first")

    vk_path = PARAMS_DIR / "membership_depth16_vk.bin"
    proof_path = FIXTURES_DIR / "depth16_proof.bin"
    assert vk_path.exists(), "missing membership verifying key"
    assert proof_path.exists(), "missing membership proof fixture"

    instance_path = tmp_path / "instance.bin"
    public_inputs_path = tmp_path / "public_inputs.bin"
    write_membership_instance_files(
        identity_scalar=1,
        blinding=2,
        merkle_path=_fixture_merkle_path(SNARK_DEPTH),
        instance_path=instance_path,
        public_inputs_path=public_inputs_path,
        depth=SNARK_DEPTH,
        schema_version=1,
    )

    result = subprocess.run(
        [
            str(VERIFY_BIN),
            "--schema",
            "v1",
            "--vk",
            str(vk_path),
            "--public-inputs",
            str(public_inputs_path),
            "--proof",
            str(proof_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "verified" in result.stdout.lower()

    assert membership_py.verify_membership_v1(
        str(vk_path),
        str(public_inputs_path),
        str(proof_path),
    )


def _fixture_merkle_path(depth: int) -> list[tuple[bytes, bool]]:
    path: list[tuple[bytes, bool]] = []
    for idx in range(depth):
        digest = hashlib.sha256(f"snark-fixture:{idx}".encode("utf-8")).digest()
        path.append((digest, idx % 2 == 0))
    return path
