"""Opt-in network tests for privacyzk protocol."""

from __future__ import annotations

import os
import socket

import pytest
import trio
from multiaddr import Multiaddr

from libp2p_privacy_poc.network.privacyzk.client import request_proof
from libp2p_privacy_poc.network.privacyzk.constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MSG_V,
    SNARK_SCHEMA_V,
)
from libp2p_privacy_poc.network.privacyzk.messages import ProofRequest
from libp2p_privacy_poc.network.privacyzk.protocol import register_privacyzk_protocol
from libp2p_privacy_poc.network.privacyzk.provider import (
    FixtureProofProvider,
    ProviderConfig,
)


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.network
@pytest.mark.trio
async def test_protocol_network_roundtrip(tmp_path) -> None:
    if os.environ.get("RUN_NETWORK_TESTS") != "1":
        pytest.skip("RUN_NETWORK_TESTS not set")
    pytest.importorskip("libp2p")
    from libp2p import new_host
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from libp2p.tools.async_service import background_trio_service

    base = tmp_path / "membership" / "v2" / f"depth-{DEFAULT_MEMBERSHIP_DEPTH}"
    base.mkdir(parents=True, exist_ok=True)
    (base / "membership_vk.bin").write_bytes(b"vk")
    (base / "public_inputs.bin").write_bytes(b"pi")
    (base / "membership_proof.bin").write_bytes(b"proof")

    host_a = new_host()
    host_b = new_host()

    provider = FixtureProofProvider(ProviderConfig(prove_mode="fixture", base_dir=str(tmp_path)))
    register_privacyzk_protocol(host_b, provider)

    async with background_trio_service(host_a.get_network()):
        async with background_trio_service(host_b.get_network()):
            port_a = _pick_free_port()
            port_b = _pick_free_port()
            await host_a.get_network().listen(Multiaddr(f"/ip4/127.0.0.1/tcp/{port_a}"))
            await host_b.get_network().listen(Multiaddr(f"/ip4/127.0.0.1/tcp/{port_b}"))
            await trio.sleep(0.2)

            addr_b = Multiaddr(f"/ip4/127.0.0.1/tcp/{port_b}").encapsulate(
                Multiaddr(f"/p2p/{host_b.get_id()}")
            )
            peer_info = info_from_p2p_addr(addr_b)
            connected = False
            last_exc: Exception | None = None
            for _ in range(10):
                try:
                    await host_a.connect(peer_info)
                    connected = True
                    break
                except Exception as exc:  # pragma: no cover - retry path
                    last_exc = exc
                    await trio.sleep(0.2)
            if not connected:
                pytest.fail(f"connect failed: {last_exc}")

            req = ProofRequest(
                msg_v=MSG_V,
                t="membership",
                schema_v=SNARK_SCHEMA_V,
                d=DEFAULT_MEMBERSHIP_DEPTH,
                nonce=b"n" * 16,
            )
            response = await request_proof(host_a, host_b.get_id(), req)
            assert response.ok is True
            assert response.t == "membership"
            assert response.public_inputs == b"pi"
            assert response.proof == b"proof"
