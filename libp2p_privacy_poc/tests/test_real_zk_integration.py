"""
Integration tests for real ZK proof helper and CLI flag behavior.
"""

import json
import pytest
from click.testing import CliRunner
from multiaddr import Multiaddr

from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyReport
from libp2p_privacy_poc.report_generator import ReportGenerator
from libp2p_privacy_poc.zk_integration import (
    generate_real_commitment_proof,
    generate_real_phase2b_proofs,
)


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


def test_generate_real_phase2b_proofs_happy_path():
    collector = _make_collector()
    results = generate_real_phase2b_proofs(collector)

    statements = {result["statement"] for result in results}
    assert statements == {
        "anon_set_membership_v1",
        "session_unlinkability_v1",
        "identity_continuity_v1",
    }
    assert all(result["backend"] == "pedersen" for result in results)
    assert all(result["verified"] is True for result in results)
    assert all(result["error"] in (None, "") for result in results)


def test_generate_real_phase2b_proofs_backend_failure(monkeypatch: pytest.MonkeyPatch):
    collector = _make_collector()

    def _raise(*args, **kwargs):
        raise RuntimeError("boom")

    from libp2p_privacy_poc.privacy_protocol import factory

    monkeypatch.setattr(factory, "get_zk_backend", _raise)
    results = generate_real_phase2b_proofs(collector)

    assert len(results) == 3
    assert all(result["verified"] is False for result in results)
    assert all(result["error"] for result in results)


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


def test_cli_with_real_phase2b_flag_calls_helper(monkeypatch: pytest.MonkeyPatch):
    from libp2p_privacy_poc import cli

    called = {"flag": False}

    def _fake(*args, **kwargs):
        called["flag"] = True
        return [
            {
                "backend": "pedersen",
                "statement": "anon_set_membership_v1",
                "peer_id": "peer-1",
                "session_id": "peer-1:1",
                "verified": True,
                "error": None,
            }
        ]

    monkeypatch.setattr(cli, "generate_real_phase2b_proofs", _fake)
    runner = CliRunner()

    result = runner.invoke(
        cli.main,
        ["analyze", "--simulate", "--duration", "1", "--with-real-phase2b"],
    )

    assert result.exit_code == 0
    assert called["flag"] is True


def test_cli_reports_data_source_label():
    from libp2p_privacy_poc import cli

    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["analyze", "--simulate", "--duration", "1"],
    )

    assert result.exit_code == 0
    assert "Data Source: SIMULATED" in result.output


def test_report_includes_real_phase2b_proofs():
    report = PrivacyReport(timestamp=0.0, overall_risk_score=0.0)
    report_gen = ReportGenerator()
    proofs = [
        {
            "backend": "pedersen",
            "statement": "anon_set_membership_v1",
            "peer_id": "peer-1",
            "session_id": "peer-1:1",
            "verified": True,
            "error": None,
        }
    ]

    console = report_gen.generate_console_report(
        report,
        real_phase2b_proofs=proofs,
    )
    assert "REAL ZK PROOFS (EXPERIMENTAL)" in console
    assert "anon_set_membership_v1" in console

    json_report = report_gen.generate_json_report(
        report,
        real_phase2b_proofs=proofs,
    )
    data = json.loads(json_report)
    assert data["real_phase2b_proofs"] == proofs
