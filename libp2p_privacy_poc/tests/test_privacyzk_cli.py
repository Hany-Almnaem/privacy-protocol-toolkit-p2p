"""CLI parsing tests for privacyzk commands."""

from __future__ import annotations

from click.testing import CliRunner

from libp2p_privacy_poc import cli


def test_zk_serve_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.main, ["zk-serve", "--help"])
    assert result.exit_code == 0


def test_zk_verify_requires_peer() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.main, ["zk-verify", "--statement", "membership"])
    assert result.exit_code != 0


def test_zk_verify_rejects_bad_depth() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "zk-verify",
            "--peer",
            "QmTestPeer123",
            "--statement",
            "continuity",
            "--depth",
            "1",
        ],
    )
    assert result.exit_code != 0
