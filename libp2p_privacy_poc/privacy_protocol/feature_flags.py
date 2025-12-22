"""
Prototype feature flags for selecting the privacy protocol backend.

WARNING: This is prototype code and backend selection affects security assumptions.
"""

from __future__ import annotations

import os
from typing import Final

_VALID_BACKENDS: Final[tuple[str, ...]] = ("mock", "pedersen", "full")
_DEFAULT_BACKEND: Final[str] = "mock"
_ENV_VAR_NAME: Final[str] = "PRIVACY_PROTOCOL_BACKEND"

_backend_override: str | None = None


def _format_valid_options() -> str:
    return ", ".join(_VALID_BACKENDS)


def _normalize_backend(value: str | None) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(
            f"Invalid backend type: {value!r}. Valid options: {_format_valid_options()}"
        )

    if value == "":
        return None

    if value not in _VALID_BACKENDS:
        raise ValueError(
            f"Invalid backend type: {value!r}. Valid options: {_format_valid_options()}"
        )

    return value


def get_backend_type(prefer: str | None = None) -> str:
    """
    Resolve backend type in precedence order.

    Args:
        prefer: Optional preferred backend type.

    Returns:
        Backend type string.

    Raises:
        ValueError: If a provided backend value is invalid.
    """
    preferred = _normalize_backend(prefer)
    if preferred is not None:
        return preferred

    if _backend_override is not None:
        return _backend_override

    env_value = os.getenv(_ENV_VAR_NAME)
    env_backend = _normalize_backend(env_value)
    if env_backend is not None:
        return env_backend

    return _DEFAULT_BACKEND


def set_backend_type(value: str | None) -> None:
    """
    Set in-memory backend override (testing only).

    Args:
        value: Backend type to force, or None to clear the override.

    Raises:
        ValueError: If the value is invalid.
    """
    global _backend_override
    _backend_override = _normalize_backend(value)
