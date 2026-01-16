"""Helpers for building SNARK continuity instances from Phase 2B inputs."""

from __future__ import annotations

from pathlib import Path


def write_continuity_instance_files(
    identity: int,
    r1: int,
    r2: int,
    out_instance: str | Path,
    out_public_inputs: str | Path,
    *,
    schema_version: int = 1,
    ctx_hash: bytes | bytearray | None = None,
) -> None:
    """
    Write SNARK continuity instance/public-input files using PyO3 bindings.
    """
    continuity_py = _load_continuity_py()

    id_bytes = _scalar_to_field_bytes(identity, "identity")
    r1_bytes = _scalar_to_field_bytes(r1, "r1")
    r2_bytes = _scalar_to_field_bytes(r2, "r2")

    if schema_version == 1:
        instance_bytes, public_inputs_bytes = continuity_py.make_continuity_instance_v1_bytes(
            id_bytes,
            r1_bytes,
            r2_bytes,
        )
    elif schema_version == 2:
        ctx_bytes = _ctx_hash_bytes(ctx_hash)
        instance_bytes, public_inputs_bytes = continuity_py.make_continuity_instance_v2_bytes(
            id_bytes,
            r1_bytes,
            r2_bytes,
            ctx_bytes,
        )
    else:
        raise ValueError("schema_version must be 1 or 2")

    instance_path = Path(out_instance)
    public_inputs_path = Path(out_public_inputs)
    instance_path.write_bytes(instance_bytes)
    public_inputs_path.write_bytes(public_inputs_bytes)


def _load_continuity_py():
    try:
        import continuity_py
    except ImportError as exc:
        raise RuntimeError(
            "continuity_py extension is not installed. Build it with maturin "
            "from privacy_circuits/continuity_py."
        ) from exc
    return continuity_py


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


DEFAULT_CTX_HASH = b"CONTINUITY_CTX_V2_______________"
