"""
Unit tests for feature flag backend selection.
"""

import pytest

from libp2p_privacy_poc.privacy_protocol import feature_flags


@pytest.fixture(autouse=True)
def reset_feature_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    feature_flags.set_backend_type(None)
    monkeypatch.delenv("PRIVACY_PROTOCOL_BACKEND", raising=False)
    yield
    feature_flags.set_backend_type(None)
    monkeypatch.delenv("PRIVACY_PROTOCOL_BACKEND", raising=False)


def test_default_backend_is_mock() -> None:
    assert feature_flags.get_backend_type() == "mock"


def test_env_var_controls_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "pedersen")
    assert feature_flags.get_backend_type() == "pedersen"


def test_prefer_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "pedersen")
    assert feature_flags.get_backend_type(prefer="full") == "full"


def test_set_backend_type_overrides_and_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "pedersen")
    feature_flags.set_backend_type("full")
    assert feature_flags.get_backend_type() == "full"
    feature_flags.set_backend_type(None)
    assert feature_flags.get_backend_type() == "pedersen"


def test_set_backend_type_empty_string_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "pedersen")
    feature_flags.set_backend_type("full")
    feature_flags.set_backend_type("")
    assert feature_flags.get_backend_type() == "pedersen"


def test_invalid_prefer_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Invalid backend type"):
        feature_flags.get_backend_type(prefer="invalid")


def test_invalid_env_raises_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "invalid")
    with pytest.raises(ValueError, match="Invalid backend type"):
        feature_flags.get_backend_type()


def test_invalid_override_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Invalid backend type"):
        feature_flags.set_backend_type("invalid")


def test_empty_env_var_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVACY_PROTOCOL_BACKEND", "")
    assert feature_flags.get_backend_type() == "mock"
