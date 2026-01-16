"""Helpers to resolve SNARK params and fixture paths with backward-compatible fallbacks."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Iterable, Tuple


def resolve_vk(
    statement: str,
    schema_version: int,
    depth: int | None = None,
    base_dir: str | Path | None = None,
) -> Path:
    return _resolve_param_path(
        "vk",
        statement,
        schema_version,
        depth=depth,
        base_dir=base_dir,
    )


def resolve_pk(
    statement: str,
    schema_version: int,
    depth: int | None = None,
    base_dir: str | Path | None = None,
) -> Path:
    return _resolve_param_path(
        "pk",
        statement,
        schema_version,
        depth=depth,
        base_dir=base_dir,
    )


def resolve_fixture_paths(
    statement: str,
    schema_version: int,
    depth: int | None = None,
    base_dir: str | Path | None = None,
) -> Tuple[Path, Path, Path]:
    """
    Resolve fixture instance/public_inputs/proof paths.
    """
    candidates = []
    depth_value = _normalize_depth(statement, depth)
    base_dir = Path(base_dir) if base_dir else _default_fixtures_dir()
    new_layout = (
        base_dir
        / statement
        / f"v{schema_version}"
        / f"depth-{depth_value}"
    )
    candidates.append((
        new_layout / "instance.bin",
        new_layout / "public_inputs.bin",
        new_layout / "proof.bin",
    ))

    if statement == "membership":
        if depth is None:
            depth_value = _normalize_depth(statement, depth)
        candidates.append((
            base_dir / "membership" / f"depth{depth_value}_instance.bin",
            base_dir / "membership" / f"depth{depth_value}_public_inputs.bin",
            base_dir / "membership" / f"depth{depth_value}_proof.bin",
        ))
        candidates.append((
            base_dir / "membership" / "instance.bin",
            base_dir / "membership" / "public_inputs.bin",
            base_dir / "membership" / "proof.bin",
        ))
    elif statement == "continuity":
        params_dir = _default_params_dir()
        suffix = "" if schema_version == 1 else f"_v{schema_version}"
        candidates.append((
            params_dir / f"continuity{suffix}_instance.bin",
            params_dir / f"continuity{suffix}_public_inputs.bin",
            params_dir / f"continuity{suffix}_proof.bin",
        ))

    return _first_existing_tuple(
        candidates,
        f"{statement} v{schema_version} fixtures",
    )


def _resolve_param_path(
    kind: str,
    statement: str,
    schema_version: int,
    depth: int | None,
    base_dir: str | Path | None,
) -> Path:
    if kind not in {"vk", "pk"}:
        raise ValueError("kind must be 'vk' or 'pk'")
    depth_value = _normalize_depth(statement, depth)
    base_dir = Path(base_dir) if base_dir else _default_params_dir()

    candidates: Iterable[Path] = []
    new_layout = (
        base_dir
        / statement
        / f"v{schema_version}"
        / f"depth-{depth_value}"
        / f"{kind}.bin"
    )
    candidates = [new_layout]

    if statement == "membership":
        if schema_version == 2:
            candidates.append(
                base_dir / f"membership_v2_depth{depth_value}_{kind}.bin"
            )
        candidates.append(base_dir / f"membership_depth{depth_value}_{kind}.bin")
        candidates.append(base_dir / f"membership_{kind}.bin")
    elif statement == "continuity":
        suffix = "" if schema_version == 1 else f"_v{schema_version}"
        candidates.append(base_dir / f"continuity{suffix}_{kind}.bin")

    return _first_existing(candidates, f"{statement} v{schema_version} {kind}")


def _normalize_depth(statement: str, depth: int | None) -> int:
    if depth is not None:
        return depth
    if statement == "membership":
        return 16
    return 0


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _default_params_dir() -> Path:
    return Path(os.getenv("SNARK_PARAMS_DIR", _default_repo_root() / "privacy_circuits" / "params"))


def _default_fixtures_dir() -> Path:
    return Path(
        os.getenv("SNARK_FIXTURES_DIR", _default_repo_root() / "privacy_circuits" / "fixtures")
    )


def _first_existing(candidates: Iterable[Path], label: str) -> Path:
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(f"Unable to resolve {label}. Checked: {', '.join(str(p) for p in candidates)}")


def _first_existing_tuple(
    candidates: Iterable[Tuple[Path, Path, Path]],
    label: str,
) -> Tuple[Path, Path, Path]:
    for instance_path, public_inputs_path, proof_path in candidates:
        if instance_path.exists() and public_inputs_path.exists() and proof_path.exists():
            return instance_path, public_inputs_path, proof_path
    checked = "; ".join(
        f"{inst}, {pub}, {proof}" for inst, pub, proof in candidates
    )
    raise FileNotFoundError(f"Unable to resolve {label}. Checked: {checked}")
