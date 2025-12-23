"""
Prototype backend factory for zero-knowledge proof systems.

WARNING: This is prototype infrastructure. Backend choice affects security
assumptions and does not provide any security guarantee. The mock backend is
for testing only and must not be used in production. This factory does not
validate cryptographic correctness.
"""

from __future__ import annotations

import importlib
import importlib.util
from typing import Final

from .feature_flags import get_backend_type
from .interfaces import ProofBackend

BACKEND_REGISTRY: Final[dict[str, str]] = {
    "mock": "privacy_protocol.adapters.mock_adapter.MockZKProofSystemAdapter",
    "pedersen": "privacy_protocol.pedersen.backend.PedersenBackend",
    # future:
    # "groth16": "privacy_protocol.snarks.groth16_backend.Groth16Backend",
}

_DEFAULT_BACKEND: Final[str] = "mock"
_PACKAGE_ROOT: Final[str] = __package__.split(".")[0] if __package__ else ""


def _format_valid_options() -> str:
    return ", ".join(sorted(BACKEND_REGISTRY.keys()))


def _normalize_backend_name(value: str | None, *, source: str) -> str | None:
    if value is None or value == "":
        return None

    if not isinstance(value, str) or value not in BACKEND_REGISTRY:
        raise ValueError(
            f"Invalid backend name from {source}: {value!r}. "
            f"Valid options: {_format_valid_options()}"
        )

    return value


def _resolve_module_path(module_path: str) -> str:
    if module_path.startswith("privacy_protocol."):
        if importlib.util.find_spec("privacy_protocol") is None and _PACKAGE_ROOT:
            return f"{_PACKAGE_ROOT}.{module_path}"
    return module_path


def _load_backend_class(backend_name: str) -> type[ProofBackend]:
    import_path = BACKEND_REGISTRY[backend_name]
    module_path, _, class_name = import_path.rpartition(".")
    if not module_path or not class_name:
        raise ValueError(
            f"Invalid backend import path for {backend_name!r}: {import_path!r}"
        )

    resolved_module_path = _resolve_module_path(module_path)
    try:
        module = importlib.import_module(resolved_module_path)
    except ModuleNotFoundError as exc:
        raise ImportError(
            f"Unable to import backend module {resolved_module_path!r} "
            f"for {backend_name!r}"
        ) from exc

    try:
        backend_cls = getattr(module, class_name)
    except AttributeError as exc:
        raise ImportError(
            f"Backend class {class_name!r} not found in module "
            f"{resolved_module_path!r}"
        ) from exc

    if not isinstance(backend_cls, type):
        raise TypeError(
            f"Backend reference {import_path!r} did not resolve to a class"
        )

    if not issubclass(backend_cls, ProofBackend):
        raise TypeError(
            f"Backend class {backend_cls.__name__!r} does not implement ProofBackend"
        )

    return backend_cls


def _resolve_backend_name(
    *, prefer: str | None = None, override: str | None = None
) -> str:
    resolved_override = _normalize_backend_name(override, source="override")
    if resolved_override is not None:
        return resolved_override

    resolved_prefer = _normalize_backend_name(prefer, source="prefer")
    if resolved_prefer is not None:
        return resolved_prefer

    resolved_flag = get_backend_type()
    if resolved_flag not in BACKEND_REGISTRY:
        raise ValueError(
            f"Invalid backend name from feature flags: {resolved_flag!r}. "
            f"Valid options: {_format_valid_options()}"
        )

    if resolved_flag:
        return resolved_flag

    if _DEFAULT_BACKEND not in BACKEND_REGISTRY:
        raise ValueError(
            f"Default backend {_DEFAULT_BACKEND!r} is not registered. "
            f"Valid options: {_format_valid_options()}"
        )

    return _DEFAULT_BACKEND


def get_zk_backend(
    *, prefer: str | None = None, override: str | None = None
) -> ProofBackend:
    """
    Return a ZK backend instance based on feature flags.

    Args:
        prefer: Optional backend name hint.
        override: Optional backend name override (testing only).

    Returns:
        ProofBackend: New backend instance.

    Raises:
        ValueError: If a backend name is invalid.
        ImportError: If the backend class cannot be imported.
        TypeError: If the backend class does not implement ProofBackend.
    """
    backend_name = _resolve_backend_name(prefer=prefer, override=override)
    backend_cls = _load_backend_class(backend_name)
    backend = backend_cls()

    if not isinstance(backend, ProofBackend):
        raise TypeError(
            f"Backend instance {backend!r} does not implement ProofBackend"
        )

    return backend
