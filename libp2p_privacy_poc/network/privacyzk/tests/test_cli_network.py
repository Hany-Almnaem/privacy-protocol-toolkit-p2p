"""Opt-in CLI network smoke test for privacyzk."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import trio
from click.testing import CliRunner
from multiaddr import Multiaddr

from libp2p_privacy_poc import cli
from libp2p_privacy_poc.network.privacyzk.protocol import register_privacyzk_protocol
from libp2p_privacy_poc.network.privacyzk.provider import (
    FixtureProofProvider,
    ProviderConfig,
)
from libp2p_privacy_poc.utils import get_peer_listening_address


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "privacy_circuits").is_dir():
            return parent
    raise RuntimeError("repo root not found")


@pytest.mark.network
@pytest.mark.trio
async def test_cli_zk_verify_network_smoke() -> None:
    if os.environ.get("RUN_NETWORK_TESTS") != "1":
        pytest.skip("RUN_NETWORK_TESTS not set")
    pytest.importorskip("libp2p")
    from libp2p import new_host
    from libp2p.tools.async_service import background_trio_service

    repo_root = _find_repo_root()
    assets_dir = repo_root / "privacy_circuits" / "params"
    if not assets_dir.is_dir():
        pytest.skip("privacy_circuits/params not available")

    host_b = new_host()
    provider = FixtureProofProvider(
        ProviderConfig(prove_mode="fixture", base_dir=str(assets_dir))
    )
    register_privacyzk_protocol(host_b, provider)

    async with background_trio_service(host_b.get_network()):
        await host_b.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
        await trio.sleep(0.2)
        addr_b = get_peer_listening_address(host_b)

        def _run_cli():
            runner = CliRunner()
            return runner.invoke(
                cli.main,
                [
                    "zk-verify",
                    "--peer",
                    str(addr_b),
                    "--statement",
                    "membership",
                    "--assets-dir",
                    str(assets_dir),
                    "--timeout",
                    "5",
                ],
            )

        result = await trio.to_thread.run_sync(_run_cli)

    assert result.exit_code == 0
    assert "PASS" in result.output
