"""
Integration tests for real ZK proof helper and CLI flag behavior.
"""

import pytest
from click.testing import CliRunner
from multiaddr import Multiaddr

from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.zk_integration import generate_real_commitment_proof


def _make_collector() -> MetadataCollector:
    collector = MetadataCollector(libp2p_host=None)
    collector.on_connection_opened(
        peer_id="QmTestPeer123",
        multiaddr=Multiaddr("/ip4/127.0.0.1/tcp/4001"),
        direction="outbound",
    )
    return collector


def test_generate_real_commitment_proof_happy_path():
    collector = _make_collector()
    result = generate_real_commitment_proof(collector)

    assert result["backend"] == "pedersen"
    assert result["statement"] == "commitment_opening_pok_v1"
    assert result["verified"] is True
    assert result["error"] in (None, "")


def test_generate_real_commitment_proof_backend_failure(monkeypatch: pytest.MonkeyPatch):
    collector = _make_collector()

    def _raise(*args, **kwargs):
        raise RuntimeError("boom")

    from libp2p_privacy_poc.privacy_protocol import factory

    monkeypatch.setattr(factory, "get_zk_backend", _raise)
    result = generate_real_commitment_proof(collector)

    assert result["verified"] is False
    assert result["error"]


def test_cli_without_real_zk_flag_skips_helper(monkeypatch: pytest.MonkeyPatch):
    from libp2p_privacy_poc import cli

    def _unexpected(*args, **kwargs):
        raise AssertionError("real ZK helper should not be called")

    monkeypatch.setattr(cli, "generate_real_commitment_proof", _unexpected)
    runner = CliRunner()

    result = runner.invoke(
        cli.main,
        ["analyze", "--simulate", "--duration", "1"],
    )

    assert result.exit_code == 0


def test_cli_with_real_zk_flag_calls_helper(monkeypatch: pytest.MonkeyPatch):
    from libp2p_privacy_poc import cli

    called = {"flag": False}

    def _fake(*args, **kwargs):
        called["flag"] = True
        return {
            "backend": "pedersen",
            "statement": "commitment_opening_pok_v1",
            "peer_id": "peer-1",
            "session_id": "peer-1:1",
            "verified": True,
            "error": None,
        }

    monkeypatch.setattr(cli, "generate_real_commitment_proof", _fake)
    runner = CliRunner()

    result = runner.invoke(
        cli.main,
        ["analyze", "--simulate", "--duration", "1", "--with-real-zk"],
    )

    assert result.exit_code == 0
    assert called["flag"] is True
