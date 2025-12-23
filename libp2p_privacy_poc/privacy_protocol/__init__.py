"""Public API for privacy_protocol (Phase 2A).
NOTE:
This module is intended for in-repo usage during Phase 2.
Importing `privacy_protocol` requires the repo root on PYTHONPATH.
Proper packaging will be addressed in a later phase.
"""
from __future__ import annotations

from importlib import import_module
from pathlib import Path
import sys
from types import ModuleType

from .factory import get_zk_backend
from .feature_flags import get_backend_type, set_backend_type
from .interfaces import AnonymitySetBackend, ProofBackend, RangeProofBackend
from .types import ProofContext, ZKProof, ZKProofType

_PARENT_PACKAGE = "libp2p_privacy_poc"


def _bootstrap_parent_package() -> None:
    if __name__ != "privacy_protocol":
        return

    if _PARENT_PACKAGE not in sys.modules:
        parent_module = ModuleType(_PARENT_PACKAGE)
        parent_module.__path__ = [
            str(Path(__file__).resolve().parent.parent)
        ]
        sys.modules[_PARENT_PACKAGE] = parent_module

    sys.modules.setdefault(
        f"{_PARENT_PACKAGE}.privacy_protocol", sys.modules[__name__]
    )

    def _alias_submodule(suffix: str) -> None:
        top_level = f"privacy_protocol.{suffix}"
        parent_level = f"{_PARENT_PACKAGE}.privacy_protocol.{suffix}"
        module = sys.modules.get(top_level)
        if module is not None:
            sys.modules.setdefault(parent_level, module)

    _alias_submodule("interfaces")
    _alias_submodule("types")
    _alias_submodule("factory")
    _alias_submodule("feature_flags")

    from . import factory as _factory

    _factory.BACKEND_REGISTRY["mock"] = (
        f"{_PARENT_PACKAGE}.privacy_protocol.adapters.mock_adapter."
        "MockZKProofSystemAdapter"
    )
    _factory.BACKEND_REGISTRY["pedersen"] = (
        f"{_PARENT_PACKAGE}.privacy_protocol.pedersen.backend.PedersenBackend"
    )


_bootstrap_parent_package()

__all__ = [
    "get_zk_backend",
    "get_backend_type",
    "set_backend_type",
    "ZKProof",
    "ProofContext",
    "ZKProofType",
    "ProofBackend",
    "AnonymitySetBackend",
    "RangeProofBackend",
    "PedersenBackend",
    "MockZKProofSystemAdapter",
]

_LAZY_EXPORTS = {
    "PedersenBackend": "pedersen.backend",
    "MockZKProofSystemAdapter": "adapters.mock_adapter",
}

_BASE_PACKAGE = (
    f"{_PARENT_PACKAGE}.privacy_protocol"
    if __name__ == "privacy_protocol"
    else __name__
)


def __getattr__(name: str):
    if name in _LAZY_EXPORTS:
        module = import_module(f"{_BASE_PACKAGE}.{_LAZY_EXPORTS[name]}")
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
