"""
DRAFT - requires crypto review before production use.

Unit tests for backend factory selection and lazy imports.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from .. import factory
from ..feature_flags import set_backend_type
from ..interfaces import ProofBackend


def _get_import_target(backend_name: str) -> tuple[str, str]:
    import_path = factory.BACKEND_REGISTRY[backend_name]
    module_path, _, class_name = import_path.rpartition(".")
    if not module_path or not class_name:
        raise RuntimeError(f"Invalid backend registry entry: {import_path!r}")
    resolved_module_path = factory._resolve_module_path(module_path)
    return resolved_module_path, class_name


@pytest.fixture(autouse=True)
def reset_factory_state(monkeypatch: pytest.MonkeyPatch) -> None:
    set_backend_type(None)
    monkeypatch.delenv("PRIVACY_PROTOCOL_BACKEND", raising=False)
    yield
    set_backend_type(None)
    monkeypatch.delenv("PRIVACY_PROTOCOL_BACKEND", raising=False)


def _assert_backend_interface(backend: ProofBackend) -> None:
    assert isinstance(backend, ProofBackend)
    assert callable(getattr(backend, "generate_proof", None))
    assert callable(getattr(backend, "verify_proof", None))
    assert callable(getattr(backend, "get_backend_info", None))


def test_default_backend_is_mock() -> None:
    backend = factory.get_zk_backend()
    _assert_backend_interface(backend)
    assert type(backend).__name__ == "MockZKProofSystemAdapter"


def test_env_var_selects_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "pedersen")
    backend = factory.get_zk_backend()
    _assert_backend_interface(backend)
    assert type(backend).__name__ == "PedersenBackend"


def test_prefer_selects_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "mock")
    backend = factory.get_zk_backend(prefer="pedersen")
    _assert_backend_interface(backend)
    assert type(backend).__name__ == "PedersenBackend"


def test_override_overrides_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "mock")
    backend = factory.get_zk_backend(prefer="invalid-backend", override="pedersen")
    _assert_backend_interface(backend)
    assert type(backend).__name__ == "PedersenBackend"


def test_invalid_backend_name_raises() -> None:
    with pytest.raises(ValueError, match="Invalid backend name"):
        factory.get_zk_backend(prefer="invalid-backend")


def test_factory_import_is_lazy() -> None:
    module_path, _ = _get_import_target("pedersen")
    saved_module = sys.modules.pop(module_path, None)
    try:
        importlib.reload(factory)
        assert module_path not in sys.modules
    finally:
        if saved_module is not None:
            sys.modules[module_path] = saved_module


def test_backend_module_imported_on_selection() -> None:
    module_path, _ = _get_import_target("pedersen")
    saved_module = sys.modules.pop(module_path, None)
    try:
        backend = factory.get_zk_backend(prefer="pedersen")
        _assert_backend_interface(backend)
        assert module_path in sys.modules
    finally:
        if saved_module is not None:
            sys.modules[module_path] = saved_module
