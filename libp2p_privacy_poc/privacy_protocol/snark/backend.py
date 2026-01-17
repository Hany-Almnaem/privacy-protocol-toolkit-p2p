"""Unified SNARK verification facade."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class _SchemaInfo:
    schema_version: int
    statement_type: int | None
    statement_version: int | None
    verifier_bytes: str


_SCHEMAS: Mapping[str, Mapping[int, _SchemaInfo]] = {
    "membership": {
        1: _SchemaInfo(
            schema_version=1,
            statement_type=None,
            statement_version=None,
            verifier_bytes="verify_membership_v1_bytes",
        ),
        2: _SchemaInfo(
            schema_version=2,
            statement_type=1,
            statement_version=2,
            verifier_bytes="verify_membership_v2_bytes",
        ),
    },
    "unlinkability": {
        2: _SchemaInfo(
            schema_version=2,
            statement_type=2,
            statement_version=2,
            verifier_bytes="verify_unlinkability_v2_bytes",
        ),
    },
    "continuity": {
        1: _SchemaInfo(
            schema_version=1,
            statement_type=None,
            statement_version=None,
            verifier_bytes="verify_continuity_v1_bytes",
        ),
        2: _SchemaInfo(
            schema_version=2,
            statement_type=3,
            statement_version=2,
            verifier_bytes="verify_continuity_v2_bytes",
        ),
    },
}

_MODULES = {
    "membership": "membership_py",
    "unlinkability": "unlinkability_py",
    "continuity": "continuity_py",
}


class SnarkBackend:
    """Verify SNARK proofs via PyO3 bindings."""

    @staticmethod
    def verify(
        statement_type: str,
        schema_version: int,
        vk_path_or_bytes: str | Path | bytes | bytearray,
        public_inputs_path_or_bytes: str | Path | bytes | bytearray,
        proof_path_or_bytes: str | Path | bytes | bytearray,
    ) -> bool:
        if statement_type not in _SCHEMAS:
            return False
        schema_map = _SCHEMAS[statement_type]
        if schema_version not in schema_map:
            return False

        schema = schema_map[schema_version]
        public_inputs_bytes = _read_bytes(public_inputs_path_or_bytes)
        if public_inputs_bytes is None:
            return False
        if not _validate_header(schema, public_inputs_bytes):
            return False

        vk_bytes = _read_bytes(vk_path_or_bytes)
        proof_bytes = _read_bytes(proof_path_or_bytes)
        if vk_bytes is None or proof_bytes is None:
            return False

        module = _load_module(statement_type)
        if module is None:
            return False
        verifier = getattr(module, schema.verifier_bytes, None)
        if verifier is None:
            return False

        try:
            return bool(verifier(vk_bytes, public_inputs_bytes, proof_bytes))
        except Exception:
            return False


def _read_bytes(value: str | Path | bytes | bytearray) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    try:
        return Path(value).read_bytes()
    except Exception:
        return None


def _validate_header(schema: _SchemaInfo, public_inputs_bytes: bytes) -> bool:
    if schema.schema_version == 1:
        if len(public_inputs_bytes) < 1:
            return False
        return public_inputs_bytes[0] == 1

    if schema.schema_version == 2:
        header = _parse_v2_header(public_inputs_bytes)
        if header is None:
            return False
        schema_version, statement_type, statement_version = header
        if schema_version != 2:
            return False
        if schema.statement_type is not None and statement_type != schema.statement_type:
            return False
        if schema.statement_version is not None and statement_version != schema.statement_version:
            return False
        return True

    return False


def _parse_v2_header(data: bytes) -> tuple[int, int, int] | None:
    if len(data) < 6:
        return None
    schema_version = int.from_bytes(data[0:2], "little")
    statement_type = int.from_bytes(data[2:4], "little")
    statement_version = int.from_bytes(data[4:6], "little")
    return schema_version, statement_type, statement_version


def _load_module(statement_type: str):
    module_name = _MODULES.get(statement_type)
    if not module_name:
        return None
    try:
        return __import__(module_name)
    except Exception:
        return None
