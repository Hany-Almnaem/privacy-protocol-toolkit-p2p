"""Integration test for SNARK membership v2 (ctx_hash + domain separation)."""

from __future__ import annotations

from pathlib import Path
import os
import subprocess

import pytest

membership_py = pytest.importorskip("membership_py")

from privacy_protocol.snark.membership import (  # noqa: E402
    write_membership_instance_files,
)
from privacy_protocol.snark.assets import resolve_pk, resolve_vk  # noqa: E402


@pytest.mark.slow
def test_membership_v2_prove_verify(tmp_path: Path) -> None:
    if os.environ.get("RUN_SLOW") != "1":
        pytest.skip("RUN_SLOW not enabled")

    try:
        pk_path = resolve_pk("membership", 2, depth=16)
        vk_path = resolve_vk("membership", 2, depth=16)
    except FileNotFoundError:
        pytest.skip("membership v2 params not available")

    depth = 16
    merkle_path = [
        (bytes([idx + 1]) * 32, idx % 2 == 0) for idx in range(depth)
    ]
    ctx_hash = b"\x11" * 32

    instance_path = tmp_path / "instance_v2.bin"
    public_inputs_path = tmp_path / "public_inputs_v2.bin"
    proof_path = tmp_path / "proof_v2.bin"

    write_membership_instance_files(
        identity_scalar=1,
        blinding=2,
        merkle_path=merkle_path,
        instance_path=instance_path,
        public_inputs_path=public_inputs_path,
        depth=depth,
        schema_version=2,
        ctx_hash=ctx_hash,
    )

    repo_root = Path(__file__).resolve().parents[3]
    prove_bin = repo_root / "privacy_circuits" / "target" / "debug" / "prove_membership"
    verify_bin = repo_root / "privacy_circuits" / "target" / "debug" / "verify_membership"

    subprocess.run(
        [
            str(prove_bin),
            "--pk",
            str(pk_path),
            "--instance",
            str(instance_path),
            "--proof-out",
            str(proof_path),
            "--schema",
            "v2",
        ],
        check=True,
    )

    verify_result = subprocess.run(
        [
            str(verify_bin),
            "--vk",
            str(vk_path),
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
    assert verify_result.returncode == 0, verify_result.stderr

    assert membership_py.verify_membership_v2(
        str(vk_path),
        str(public_inputs_path),
        str(proof_path),
    )
