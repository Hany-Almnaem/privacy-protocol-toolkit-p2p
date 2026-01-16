"""Helpers for building SNARK membership instances from Phase 2B inputs."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple


def build_membership_instance_bytes(
    identity_scalar,
    blinding,
    merkle_path: Iterable[Tuple[bytes, bool]] | Iterable[dict],
    *,
    depth: int | None = None,
    schema_version: int = 1,
    ctx_hash: bytes | bytearray | None = None,
):
    """
    Build bincode-encoded instance/public-inputs for the SNARK membership circuit.

    Notes:
        - This helper maps Phase 2B scalars and Merkle sibling bytes into the BN254 field.
        - The Poseidon-based root is recomputed using the provided sibling values.
        - This does not preserve SHA-256 Merkle semantics from Phase 2B.
    """
    membership_py = _load_membership_py()

    identity_bytes = _scalar_to_field_bytes(identity_scalar, "identity_scalar")
    blinding_bytes = _scalar_to_field_bytes(blinding, "blinding")

    siblings: list[bytes] = []
    is_left: list[bool] = []
    for idx, entry in enumerate(merkle_path):
        sibling, left = _parse_merkle_entry(entry, idx)
        siblings.append(_field_bytes(sibling, f"merkle_path[{idx}].sibling"))
        is_left.append(left)

    if depth is None:
        depth = len(siblings)

    if depth != len(siblings):
        raise ValueError("depth must match merkle_path length")

    if schema_version == 0:
        return membership_py.make_membership_instance_bytes(
            identity_bytes,
            blinding_bytes,
            siblings,
            is_left,
        )

    if schema_version == 2:
        ctx_bytes = _ctx_hash_bytes(ctx_hash)
        return membership_py.make_membership_instance_v2_bytes(
            identity_bytes,
            blinding_bytes,
            siblings,
            is_left,
            ctx_bytes,
        )

    if schema_version != 1:
        raise ValueError("schema_version must be 0, 1, or 2")

    return membership_py.make_membership_instance_v1_bytes(
        identity_bytes,
        blinding_bytes,
        siblings,
        is_left,
    )


def write_membership_instance_files(
    identity_scalar,
    blinding,
    merkle_path: Iterable[Tuple[bytes, bool]] | Iterable[dict],
    instance_path: str | Path,
    public_inputs_path: str | Path,
    *,
    depth: int | None = None,
    schema_version: int = 1,
    ctx_hash: bytes | bytearray | None = None,
) -> tuple[Path, Path]:
    """
    Write SNARK instance/public-input files from Phase 2B inputs.
    """
    instance_bytes, public_inputs_bytes = build_membership_instance_bytes(
        identity_scalar,
        blinding,
        merkle_path,
        depth=depth,
        schema_version=schema_version,
        ctx_hash=ctx_hash,
    )
    instance_path = Path(instance_path)
    public_inputs_path = Path(public_inputs_path)

    instance_path.write_bytes(instance_bytes)
    public_inputs_path.write_bytes(public_inputs_bytes)

    return instance_path, public_inputs_path


def _load_membership_py():
    try:
        import membership_py
    except ImportError as exc:
        raise RuntimeError(
            "membership_py extension is not installed. Build it with maturin "
            "from privacy_circuits/membership_py."
        ) from exc
    return membership_py


def _parse_merkle_entry(entry, idx: int) -> tuple[bytes, bool]:
    if isinstance(entry, dict):
        if "sibling" not in entry or "is_left" not in entry:
            raise ValueError(
                f"merkle_path[{idx}] must include 'sibling' and 'is_left' keys"
            )
        sibling = entry["sibling"]
        is_left = entry["is_left"]
    else:
        try:
            sibling, is_left = entry
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"merkle_path[{idx}] must be (sibling, is_left) or dict"
            ) from exc

    if not isinstance(is_left, bool):
        raise TypeError(f"merkle_path[{idx}].is_left must be bool")

    if not isinstance(sibling, (bytes, bytearray)):
        raise TypeError(f"merkle_path[{idx}].sibling must be bytes")

    return bytes(sibling), is_left


def _scalar_to_field_bytes(value, label: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return _field_bytes(bytes(value), label)

    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{label} must be non-negative")
        raw = value.to_bytes(32, byteorder="big")
        return _field_bytes(raw, label)

    binary = getattr(value, "binary", None)
    if callable(binary):
        return _field_bytes(binary(), label)

    raise TypeError(f"{label} must be bytes, int, or petlib.Bn-like")


def _field_bytes(data: bytes, label: str) -> bytes:
    if not data:
        raise ValueError(f"{label} cannot be empty")
    if len(data) > 32:
        raise ValueError(f"{label} must be at most 32 bytes")
    if len(data) < 32:
        data = data.rjust(32, b"\x00")
    return data


def _ctx_hash_bytes(ctx_hash: bytes | bytearray | None) -> bytes:
    if ctx_hash is None:
        return DEFAULT_CTX_HASH
    if not isinstance(ctx_hash, (bytes, bytearray)):
        raise TypeError("ctx_hash must be bytes")
    return _field_bytes(bytes(ctx_hash), "ctx_hash")


DEFAULT_CTX_HASH = b"MEMBERSHIP_CTX_V2_______________"
