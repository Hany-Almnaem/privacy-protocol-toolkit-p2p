"""Fixture resolver for privacy proof artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MAX_INSTANCE_BYTES,
    MAX_PK_BYTES,
    MAX_PROOF_BYTES,
    MAX_PUBLIC_INPUTS_BYTES,
    SNARK_SCHEMA_V,
    STATEMENT_TYPES,
)
from .errors import SchemaError, SizeLimitError

MAX_VK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class FixturePaths:
    vk_path: Path
    public_inputs_path: Path
    proof_path: Path


@dataclass(frozen=True)
class ProverPaths:
    pk_path: Path
    instance_path: Path
    public_inputs_path: Path


class AssetsResolver:
    def __init__(self, base_dir: Path | str = "privacy_circuits/params") -> None:
        self._base_dir = Path(base_dir)

    def resolve_fixture(
        self, statement_type: str, schema_v: int, depth: int
    ) -> FixturePaths:
        self._validate_request(statement_type, schema_v, depth)
        base = self._base_dir / statement_type / f"v{schema_v}" / f"depth-{depth}"
        if not base.exists() or not base.is_dir():
            raise SchemaError(f"fixture directory missing: {base}")

        vk_path = self._resolve_one(base, self._vk_candidates(statement_type), "vk")
        public_inputs_path = self._resolve_one(
            base, self._public_inputs_candidates(statement_type), "public_inputs"
        )
        proof_path = self._resolve_one(base, self._proof_candidates(statement_type), "proof")

        self._check_size(vk_path, MAX_VK_BYTES, "vk")
        self._check_size(public_inputs_path, MAX_PUBLIC_INPUTS_BYTES, "public_inputs")
        self._check_size(proof_path, MAX_PROOF_BYTES, "proof")

        return FixturePaths(
            vk_path=vk_path, public_inputs_path=public_inputs_path, proof_path=proof_path
        )

    def resolve_prover_inputs(
        self, statement_type: str, schema_v: int, depth: int
    ) -> ProverPaths:
        self._validate_request(statement_type, schema_v, depth)
        base = self._base_dir / statement_type / f"v{schema_v}" / f"depth-{depth}"
        if not base.exists() or not base.is_dir():
            raise SchemaError(f"prover directory missing: {base}")

        pk_path = self._resolve_one(base, self._pk_candidates(statement_type), "pk")
        instance_path = self._resolve_one(
            base, self._instance_candidates(statement_type), "instance"
        )
        public_inputs_path = self._resolve_one(
            base, self._public_inputs_candidates(statement_type), "public_inputs"
        )

        self._check_size(pk_path, MAX_PK_BYTES, "pk")
        self._check_size(instance_path, MAX_INSTANCE_BYTES, "instance")
        self._check_size(public_inputs_path, MAX_PUBLIC_INPUTS_BYTES, "public_inputs")

        return ProverPaths(
            pk_path=pk_path,
            instance_path=instance_path,
            public_inputs_path=public_inputs_path,
        )

    def _validate_request(self, statement_type: str, schema_v: int, depth: int) -> None:
        if statement_type not in STATEMENT_TYPES:
            raise SchemaError("unsupported statement type")
        if schema_v != SNARK_SCHEMA_V:
            raise SchemaError("unsupported schema_v")
        if statement_type == "membership":
            if depth != DEFAULT_MEMBERSHIP_DEPTH:
                raise SchemaError("unsupported membership depth")
        else:
            if depth != 0:
                raise SchemaError("unsupported depth for statement")

    def _resolve_one(
        self, base: Path, candidates: Iterable[str], label: str
    ) -> Path:
        for name in candidates:
            path = base / name
            if path.exists() and path.is_file():
                return path
        raise SchemaError(f"missing {label} fixture in {base}")

    def _check_size(self, path: Path, limit: int, label: str) -> None:
        size = path.stat().st_size
        if size > limit:
            raise SizeLimitError(f"{label} size exceeds limit")

    @staticmethod
    def _vk_candidates(statement_type: str) -> tuple[str, ...]:
        if statement_type == "membership":
            return ("membership_vk.bin", "vk.bin")
        if statement_type == "continuity":
            return ("continuity_vk.bin", "vk.bin")
        return ("unlinkability_vk.bin", "vk.bin")

    @staticmethod
    def _public_inputs_candidates(statement_type: str) -> tuple[str, ...]:
        if statement_type == "membership":
            return ("public_inputs.bin", "membership_public_inputs.bin")
        if statement_type == "continuity":
            return ("continuity_public_inputs.bin", "public_inputs.bin")
        return ("unlinkability_public_inputs.bin", "public_inputs.bin")

    @staticmethod
    def _proof_candidates(statement_type: str) -> tuple[str, ...]:
        if statement_type == "membership":
            return ("membership_proof.bin", "proof.bin")
        if statement_type == "continuity":
            return ("continuity_proof.bin", "proof.bin")
        return ("unlinkability_proof.bin", "proof.bin")

    @staticmethod
    def _pk_candidates(statement_type: str) -> tuple[str, ...]:
        if statement_type == "membership":
            return ("pk.bin", "membership_pk.bin")
        if statement_type == "continuity":
            return ("pk.bin", "continuity_pk.bin")
        return ("pk.bin", "unlinkability_pk.bin")

    @staticmethod
    def _instance_candidates(statement_type: str) -> tuple[str, ...]:
        if statement_type == "membership":
            return ("instance.bin", "membership_instance.bin")
        if statement_type == "continuity":
            return ("instance.bin", "continuity_instance.bin")
        return ("instance.bin", "unlinkability_instance.bin")
