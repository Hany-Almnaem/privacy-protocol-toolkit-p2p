"""Integration tests for SNARK continuity v1 verification via Python bindings."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

continuity_py = pytest.importorskip("continuity_py")

from privacy_protocol.snark.continuity import (  # noqa: E402
    write_continuity_instance_files,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
PARAMS_DIR = REPO_ROOT / "privacy_circuits/params"
PROVE_BIN = REPO_ROOT / "privacy_circuits/target/debug/prove_continuity"
VERIFY_BIN = REPO_ROOT / "privacy_circuits/target/debug/verify_continuity"


def _require_assets() -> None:
    if not PROVE_BIN.exists():
        pytest.skip("prove_continuity binary missing; build continuity crate first")
    if not VERIFY_BIN.exists():
        pytest.skip("verify_continuity binary missing; build continuity crate first")
    if not (PARAMS_DIR / "continuity_pk.bin").exists():
        pytest.skip("continuity proving key missing")
    if not (PARAMS_DIR / "continuity_vk.bin").exists():
        pytest.skip("continuity verifying key missing")


@pytest.mark.slow
def test_continuity_v1_end_to_end(tmp_path: Path) -> None:
    _require_assets()

    instance_path = tmp_path / "continuity_instance.bin"
    public_inputs_path = tmp_path / "continuity_public_inputs.bin"
    proof_path = tmp_path / "continuity_proof.bin"

    write_continuity_instance_files(
        identity=1,
        r1=2,
        r2=3,
        out_instance=instance_path,
        out_public_inputs=public_inputs_path,
    )

    result = subprocess.run(
        [
            str(PROVE_BIN),
            "--pk",
            str(PARAMS_DIR / "continuity_pk.bin"),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
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
            str(PARAMS_DIR / "continuity_vk.bin"),
            "--public-inputs",
            str(public_inputs_path),
            "--proof",
            str(proof_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stderr
    assert "verified" in verify.stdout.lower()

    assert continuity_py.verify_continuity_v1(
        str(PARAMS_DIR / "continuity_vk.bin"),
        str(public_inputs_path),
        str(proof_path),
    )


@pytest.mark.slow
def test_continuity_v1_tamper_proof_fails(tmp_path: Path) -> None:
    _require_assets()

    instance_path = tmp_path / "continuity_instance.bin"
    public_inputs_path = tmp_path / "continuity_public_inputs.bin"
    proof_path = tmp_path / "continuity_proof.bin"

    write_continuity_instance_files(
        identity=1,
        r1=2,
        r2=3,
        out_instance=instance_path,
        out_public_inputs=public_inputs_path,
    )

    subprocess.run(
        [
            str(PROVE_BIN),
            "--pk",
            str(PARAMS_DIR / "continuity_pk.bin"),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    proof_bytes = bytearray(proof_path.read_bytes())
    proof_bytes[-1] ^= 0x01
    tampered_proof = tmp_path / "continuity_proof_tampered.bin"
    tampered_proof.write_bytes(bytes(proof_bytes))

    verify = subprocess.run(
        [
            str(VERIFY_BIN),
            "--vk",
            str(PARAMS_DIR / "continuity_vk.bin"),
            "--public-inputs",
            str(public_inputs_path),
            "--proof",
            str(tampered_proof),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode != 0

    assert not _verify_with_pyo3(
        PARAMS_DIR / "continuity_vk.bin",
        public_inputs_path,
        tampered_proof,
    )


@pytest.mark.slow
def test_continuity_v1_tamper_public_inputs_fails(tmp_path: Path) -> None:
    _require_assets()

    instance_path = tmp_path / "continuity_instance.bin"
    public_inputs_path = tmp_path / "continuity_public_inputs.bin"
    proof_path = tmp_path / "continuity_proof.bin"

    write_continuity_instance_files(
        identity=1,
        r1=2,
        r2=3,
        out_instance=instance_path,
        out_public_inputs=public_inputs_path,
    )

    subprocess.run(
        [
            str(PROVE_BIN),
            "--pk",
            str(PARAMS_DIR / "continuity_pk.bin"),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    public_inputs_bytes = bytearray(public_inputs_path.read_bytes())
    public_inputs_bytes[0] ^= 0x01
    tampered_inputs = tmp_path / "continuity_public_inputs_tampered.bin"
    tampered_inputs.write_bytes(bytes(public_inputs_bytes))

    verify = subprocess.run(
        [
            str(VERIFY_BIN),
            "--vk",
            str(PARAMS_DIR / "continuity_vk.bin"),
            "--public-inputs",
            str(tampered_inputs),
            "--proof",
            str(proof_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode != 0

    assert not _verify_with_pyo3(
        PARAMS_DIR / "continuity_vk.bin",
        tampered_inputs,
        proof_path,
    )


def _verify_with_pyo3(vk_path: Path, public_inputs: Path, proof: Path) -> bool:
    try:
        return continuity_py.verify_continuity_v1(
            str(vk_path),
            str(public_inputs),
            str(proof),
        )
    except Exception:
        return False
