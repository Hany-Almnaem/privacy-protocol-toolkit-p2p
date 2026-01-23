"""Unit tests for privacyzk integration orchestration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from libp2p_privacy_poc.network.privacyzk import integration
from libp2p_privacy_poc.network.privacyzk.messages import ProofResponse


def _make_collector(peer_id: str = "QmPeer1") -> SimpleNamespace:
    peer_meta = SimpleNamespace(multiaddrs={f"/ip4/127.0.0.1/tcp/4001"})
    return SimpleNamespace(peers={peer_id: peer_meta})


def test_try_real_proofs_offline_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"flag": False}

    def _exchange(*args, **kwargs):
        called["flag"] = True
        raise AssertionError("exchange should not be called")

    monkeypatch.setattr(integration, "_exchange", _exchange)
    result = integration.try_real_proofs(_make_collector(), offline=True)
    assert result.attempted is False
    assert called["flag"] is False


def test_try_real_proofs_no_peers() -> None:
    collector = SimpleNamespace(peers={})
    result = integration.try_real_proofs(collector)
    assert result.attempted is False


def test_try_real_proofs_exchange_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _exchange(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(integration, "_exchange", _exchange)
    result = integration.try_real_proofs(_make_collector())
    assert result.attempted is True
    assert result.success is False
    assert result.fallback_reason


def test_try_real_proofs_exchange_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def _exchange(*args, **kwargs):
        return [
            {
                "backend": "snark-network",
                "statement": "membership_v2",
                "peer_id": "QmPeer1",
                "schema_v": 2,
                "depth": 16,
                "verified": True,
                "error": None,
            }
        ]

    monkeypatch.setattr(integration, "_exchange", _exchange)
    result = integration.try_real_proofs(_make_collector())
    assert result.attempted is True
    assert result.success is True
    assert result.results[0]["verified"] is True
