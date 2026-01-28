"""Real prover callback for privacy proof exchange."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .assets import AssetsResolver, ProverPaths
from .constants import SNARK_SCHEMA_V
from .errors import SchemaError
from .messages import ProofRequest
from .provider import ProverCallback

DEFAULT_PROVER_TIMEOUT = 120


@dataclass(frozen=True)
class ProverContext:
    assets_dir: Path
    repo_root: Path


def make_real_prover_callback(
    assets_dir: Path | str = "privacy_circuits/params",
    repo_root: Optional[Path] = None,
) -> ProverCallback:
    context = _build_context(assets_dir, repo_root)
    resolver = AssetsResolver(context.assets_dir)

    def _prover(req: ProofRequest) -> tuple[bytes, bytes, dict]:
        if req.schema_v != SNARK_SCHEMA_V:
            raise SchemaError("unsupported schema_v")

        paths = resolver.resolve_prover_inputs(req.t, req.schema_v, req.d)
        prover_path = _find_prover_binary(context.repo_root, req.t)

        with tempfile.TemporaryDirectory() as tmp_dir:
            proof_path = Path(tmp_dir) / "proof.bin"
            _run_prover(
                prover_path=prover_path,
                pk_path=paths.pk_path,
                instance_path=paths.instance_path,
                proof_path=proof_path,
                schema=f"v{req.schema_v}",
            )
            proof_bytes = proof_path.read_bytes()

        public_inputs = paths.public_inputs_path.read_bytes()
        meta = {
            "prover": "rust",
            "prover_path": str(prover_path),
            "pk_path": str(paths.pk_path),
            "instance_path": str(paths.instance_path),
            "public_inputs_path": str(paths.public_inputs_path),
            "schema": f"v{req.schema_v}",
        }
        return public_inputs, proof_bytes, meta

    return _prover


def _build_context(assets_dir: Path | str, repo_root: Optional[Path]) -> ProverContext:
    assets_path = Path(assets_dir)
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[3]
    return ProverContext(assets_dir=assets_path, repo_root=repo_root)


def _find_prover_binary(repo_root: Path, statement_type: str) -> Path:
    name = f"prove_{statement_type}"
    debug_path = repo_root / "privacy_circuits" / "target" / "debug" / name
    if debug_path.exists():
        return debug_path
    release_path = repo_root / "privacy_circuits" / "target" / "release" / name
    if release_path.exists():
        return release_path
    return debug_path


def _run_prover(
    *,
    prover_path: Path,
    pk_path: Path,
    instance_path: Path,
    proof_path: Path,
    schema: str,
) -> None:
    if not prover_path.exists():
        raise FileNotFoundError(f"missing prover binary: {prover_path}")
    if not pk_path.exists():
        raise FileNotFoundError(f"missing proving key: {pk_path}")
    if not instance_path.exists():
        raise FileNotFoundError(f"missing instance: {instance_path}")

    command = [
        str(prover_path),
        "--pk",
        str(pk_path),
        "--instance",
        str(instance_path),
        "--proof-out",
        str(proof_path),
        "--schema",
        schema,
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=DEFAULT_PROVER_TIMEOUT,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "unknown prover error"
        raise RuntimeError(f"prover failed: {stderr}")
