"""Integration tests for SNARK unlinkability v2 verification via Python bindings."""

from __future__ import annotations

from pathlib import Path
import os
import subprocess

import pytest

unlinkability_py = pytest.importorskip("unlinkability_py")

from privacy_protocol.snark.unlinkability import (  # noqa: E402
    write_unlinkability_instance_files,
)
from privacy_protocol.snark.assets import resolve_pk, resolve_vk  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parents[3]
PROVE_BIN = REPO_ROOT / "privacy_circuits/target/debug/prove_unlinkability"
VERIFY_BIN = REPO_ROOT / "privacy_circuits/target/debug/verify_unlinkability"

PUBLIC_INPUTS_HEADER = 2 + 2 + 2
TAG_OFFSET = PUBLIC_INPUTS_HEADER
DOMAIN_SEP_OFFSET = TAG_OFFSET + 32
CTX_HASH_OFFSET = DOMAIN_SEP_OFFSET + 32


def _require_assets() -> None:
    if os.environ.get("RUN_SLOW") != "1":
        pytest.skip("RUN_SLOW not enabled")
    if not PROVE_BIN.exists():
        pytest.skip("prove_unlinkability binary missing; build unlinkability crate first")
    if not VERIFY_BIN.exists():
        pytest.skip("verify_unlinkability binary missing; build unlinkability crate first")
    try:
        resolve_pk("unlinkability", 2)
        resolve_vk("unlinkability", 2)
    except FileNotFoundError:
        pytest.skip("unlinkability v2 params not available")


@pytest.mark.slow
def test_unlinkability_v2_end_to_end(tmp_path: Path) -> None:
    _require_assets()

    instance_path = tmp_path / "unlinkability_v2_instance.bin"
    public_inputs_path = tmp_path / "unlinkability_v2_public_inputs.bin"
    proof_path = tmp_path / "unlinkability_v2_proof.bin"

    write_unlinkability_instance_files(
        identity=7,
        blinding=9,
        out_instance=instance_path,
        out_public_inputs=public_inputs_path,
        schema_version=2,
        ctx_hash=b"\x11" * 32,
    )

    result = subprocess.run(
        [
            str(PROVE_BIN),
            "--pk",
            str(resolve_pk("unlinkability", 2)),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert proof_path.exists()

    verify = subprocess.run(
        [
            str(VERIFY_BIN),
            "--vk",
            str(resolve_vk("unlinkability", 2)),
            "--public-inputs",
            str(public_inputs_path),
            "--proof",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stderr
    assert "verified" in verify.stdout.lower()

    assert unlinkability_py.verify_unlinkability_v2(
        str(resolve_vk("unlinkability", 2)),
        str(public_inputs_path),
        str(proof_path),
    )


@pytest.mark.slow
def test_unlinkability_v2_tamper_domain_sep_fails(tmp_path: Path) -> None:
    _require_assets()

    instance_path = tmp_path / "unlinkability_v2_instance.bin"
    public_inputs_path = tmp_path / "unlinkability_v2_public_inputs.bin"
    proof_path = tmp_path / "unlinkability_v2_proof.bin"

    write_unlinkability_instance_files(
        identity=7,
        blinding=9,
        out_instance=instance_path,
        out_public_inputs=public_inputs_path,
        schema_version=2,
        ctx_hash=b"\x22" * 32,
    )

    subprocess.run(
        [
            str(PROVE_BIN),
            "--pk",
            str(resolve_pk("unlinkability", 2)),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    public_inputs_bytes = bytearray(public_inputs_path.read_bytes())
    public_inputs_bytes[DOMAIN_SEP_OFFSET] ^= 0x01
    tampered_inputs = tmp_path / "unlinkability_v2_public_inputs_tampered.bin"
    tampered_inputs.write_bytes(bytes(public_inputs_bytes))

    verify = subprocess.run(
        [
            str(VERIFY_BIN),
            "--vk",
            str(resolve_vk("unlinkability", 2)),
            "--public-inputs",
            str(tampered_inputs),
            "--proof",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode != 0

    assert not _verify_with_pyo3(resolve_vk("unlinkability", 2), tampered_inputs, proof_path)


@pytest.mark.slow
def test_unlinkability_v2_tamper_ctx_hash_fails(tmp_path: Path) -> None:
    _require_assets()

    instance_path = tmp_path / "unlinkability_v2_instance.bin"
    public_inputs_path = tmp_path / "unlinkability_v2_public_inputs.bin"
    proof_path = tmp_path / "unlinkability_v2_proof.bin"

    write_unlinkability_instance_files(
        identity=7,
        blinding=9,
        out_instance=instance_path,
        out_public_inputs=public_inputs_path,
        schema_version=2,
        ctx_hash=b"\x33" * 32,
    )

    subprocess.run(
        [
            str(PROVE_BIN),
            "--pk",
            str(resolve_pk("unlinkability", 2)),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    public_inputs_bytes = bytearray(public_inputs_path.read_bytes())
    public_inputs_bytes[CTX_HASH_OFFSET] ^= 0x01
    tampered_inputs = tmp_path / "unlinkability_v2_public_inputs_tampered.bin"
    tampered_inputs.write_bytes(bytes(public_inputs_bytes))

    verify = subprocess.run(
        [
            str(VERIFY_BIN),
            "--vk",
            str(resolve_vk("unlinkability", 2)),
            "--public-inputs",
            str(tampered_inputs),
            "--proof",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode != 0

    assert not _verify_with_pyo3(resolve_vk("unlinkability", 2), tampered_inputs, proof_path)


@pytest.mark.slow
def test_unlinkability_v2_tamper_tag_fails(tmp_path: Path) -> None:
    _require_assets()

    instance_path = tmp_path / "unlinkability_v2_instance.bin"
    public_inputs_path = tmp_path / "unlinkability_v2_public_inputs.bin"
    proof_path = tmp_path / "unlinkability_v2_proof.bin"

    write_unlinkability_instance_files(
        identity=7,
        blinding=9,
        out_instance=instance_path,
        out_public_inputs=public_inputs_path,
        schema_version=2,
        ctx_hash=b"\x44" * 32,
    )

    subprocess.run(
        [
            str(PROVE_BIN),
            "--pk",
            str(resolve_pk("unlinkability", 2)),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    public_inputs_bytes = bytearray(public_inputs_path.read_bytes())
    public_inputs_bytes[TAG_OFFSET] ^= 0x01
    tampered_inputs = tmp_path / "unlinkability_v2_public_inputs_tampered.bin"
    tampered_inputs.write_bytes(bytes(public_inputs_bytes))

    verify = subprocess.run(
        [
            str(VERIFY_BIN),
            "--vk",
            str(resolve_vk("unlinkability", 2)),
            "--public-inputs",
            str(tampered_inputs),
            "--proof",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode != 0

    assert not _verify_with_pyo3(resolve_vk("unlinkability", 2), tampered_inputs, proof_path)


def _verify_with_pyo3(vk_path: Path, public_inputs_path: Path, proof_path: Path) -> bool:
    try:
        return unlinkability_py.verify_unlinkability_v2(
            str(vk_path),
            str(public_inputs_path),
            str(proof_path),
        )
    except Exception:
        return False
