"""Best-effort SNARK proof exchange orchestrator."""

from __future__ import annotations

import secrets
import time
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import cbor2
import trio
from multiaddr import Multiaddr

from libp2p_privacy_poc.privacy_protocol.snark.backend import SnarkBackend

from .assets import AssetsResolver
from .client import request_proof
from .constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MSG_V,
    PROTOCOL_ID,
    SNARK_SCHEMA_V,
    STATEMENT_TYPES,
)
from .messages import ProofRequest


_STATEMENT_LABELS = {
    "membership": "membership_v2",
    "continuity": "continuity_v2",
    "unlinkability": "unlinkability_v2",
}


@dataclass(frozen=True)
class ProofExchangeResult:
    attempted: bool
    success: bool
    results: List[Dict[str, Any]]
    fallback_reason: Optional[str]
    summary: Optional[Dict[str, Any]] = None


def try_real_proofs(
    collector: Any,
    *,
    statement: str = "membership",
    statements: Optional[Iterable[str]] = None,
    assets_dir: str = "privacy_circuits/params",
    timeout: float = 8.0,
    zk_peer: Optional[str] = None,
    offline: bool = False,
    require_real: bool = False,
) -> ProofExchangeResult:
    if offline:
        return ProofExchangeResult(False, False, [], None)

    peer_id, peer_addr = _select_peer(collector, zk_peer)
    if not peer_id:
        return ProofExchangeResult(False, False, [], None)

    if statements is None:
        requested = [statement]
    else:
        requested = list(statements)
    normalized = [item.lower() for item in requested if item]
    invalid = [item for item in normalized if item not in STATEMENT_TYPES]
    if invalid:
        return ProofExchangeResult(
            True,
            False,
            [_error_result(item, peer_id, "unsupported statement") for item in invalid],
            "unsupported statement",
            summary=_build_summary(peer_addr, normalized, []),
        )

    try:
        results = _exchange(
            peer_id,
            peer_addr,
            normalized,
            assets_dir,
            timeout,
        )
    except Exception as exc:
        results = [_error_result(statement, peer_id, str(exc))]
        return ProofExchangeResult(
            True,
            False,
            results,
            "Real ZK proof exchange unavailable; falling back to legacy simulation.",
            summary=_build_summary(peer_addr, normalized, results),
        )

    if require_real:
        for item in results:
            if item.get("prove_mode") != "real":
                item["verified"] = False
                if not item.get("error"):
                    mode = item.get("prove_mode") or "unknown"
                    item["error"] = f"expected prove_mode=real, got {mode}"

    success = all(item.get("verified") for item in results)
    fallback_reason = None
    if not success:
        fallback_reason = (
            "Real ZK proof exchange unavailable; falling back to legacy simulation."
        )
    return ProofExchangeResult(
        True,
        success,
        results,
        fallback_reason,
        summary=_build_summary(peer_addr, normalized, results),
    )


def _exchange(
    peer_id: str,
    peer_addr: Optional[str],
    statements: Iterable[str],
    assets_dir: str,
    timeout: float,
) -> List[Dict[str, Any]]:
    return trio.run(
        _exchange_async,
        peer_id,
        peer_addr,
        list(statements),
        assets_dir,
        timeout,
    )


async def _exchange_async(
    peer_id: str,
    peer_addr: Optional[str],
    statements: List[str],
    assets_dir: str,
    timeout: float,
) -> List[Dict[str, Any]]:
    from libp2p import new_host
    from libp2p.peer.id import ID
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from libp2p.tools.async_service import background_trio_service

    host = new_host()
    network = host.get_network()
    resolver = AssetsResolver(assets_dir)
    results: List[Dict[str, Any]] = []
    peer_id_obj = None
    peer_id_label = peer_id

    async with background_trio_service(network):
        await network.listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
        await trio.sleep(0.2)

        if peer_addr:
            peer_info = info_from_p2p_addr(Multiaddr(peer_addr))
            await host.connect(peer_info)
            peer_id_obj = peer_info.peer_id
            peer_id_label = _format_peer_id(peer_id_obj)
        else:
            try:
                peer_id_obj = ID.from_base58(peer_id)
                peer_id_label = _format_peer_id(peer_id_obj)
            except Exception:
                return [
                    _error_result(statement, peer_id_label, "invalid peer id")
                    for statement in statements
                ]

        for statement in statements:
            depth = DEFAULT_MEMBERSHIP_DEPTH if statement == "membership" else 0
            req = ProofRequest(
                msg_v=MSG_V,
                t=statement,
                schema_v=SNARK_SCHEMA_V,
                d=depth,
                nonce=secrets.token_bytes(16),
            )
            result = {
                "backend": "snark-network",
                "statement": _STATEMENT_LABELS.get(statement, statement),
                "peer_id": peer_id_label,
                "peer_addr": peer_addr,
                "protocol_id": PROTOCOL_ID,
                "schema_v": SNARK_SCHEMA_V,
                "depth": depth,
                "verified": False,
                "error": None,
                "verify_ms": None,
                "exchange_ms": None,
                "asset_source": None,
            }
            exchange_start = time.perf_counter()
            try:
                with trio.fail_after(timeout):
                    response = await request_proof(
                        host, peer_id_obj, req, timeout=timeout
                    )
                _update_from_response(result, response)
                if not response.ok:
                    result["error"] = response.err or "proof request failed"
                    results.append(result)
                    continue
                if response.t != statement or response.schema_v != SNARK_SCHEMA_V:
                    result["error"] = "response metadata mismatch"
                    results.append(result)
                    continue
                if response.d != depth:
                    result["error"] = "response depth mismatch"
                    results.append(result)
                    continue
                fixture = resolver.resolve_fixture(statement, SNARK_SCHEMA_V, depth)
                result["asset_source"] = {
                    "type": "vk",
                    "path": str(fixture.vk_path),
                    "sha256": _hash_file(fixture.vk_path),
                }
                verify_start = time.perf_counter()
                verified = SnarkBackend.verify(
                    statement_type=statement,
                    schema_version=SNARK_SCHEMA_V,
                    vk=str(fixture.vk_path),
                    public_inputs=response.public_inputs,
                    proof=response.proof,
                )
                result["verify_ms"] = round(
                    (time.perf_counter() - verify_start) * 1000.0, 3
                )
                result["verified"] = bool(verified)
                if not verified:
                    result["error"] = "verification failed"
            except Exception as exc:
                result["error"] = str(exc)
            finally:
                result["exchange_ms"] = round(
                    (time.perf_counter() - exchange_start) * 1000.0, 3
                )
            results.append(result)

    await host.close()
    return results


def _select_peer(
    collector: Any, zk_peer: Optional[str]
) -> Tuple[Optional[str], Optional[str]]:
    if zk_peer:
        if zk_peer.startswith("/"):
            try:
                addr = Multiaddr(zk_peer)
                if "/p2p/" in zk_peer:
                    peer_id = str(addr.get_peer_id())
                    return peer_id, zk_peer
            except Exception:
                return None, None
        else:
            addr = _lookup_multiaddr(collector, zk_peer)
            return zk_peer, addr

    if not getattr(collector, "peers", None):
        return None, None

    for peer_id, meta in collector.peers.items():
        addr = _lookup_multiaddr(collector, peer_id)
        if addr:
            return peer_id, addr

    return None, None


def _lookup_multiaddr(collector: Any, peer_id: str) -> Optional[str]:
    if not getattr(collector, "peers", None):
        return None
    meta = collector.peers.get(peer_id)
    if not meta or not getattr(meta, "multiaddrs", None):
        return None
    for addr in meta.multiaddrs:
        if not addr:
            continue
        if "/p2p/" in addr:
            return addr
        return f"{addr}/p2p/{peer_id}"
    return None


def _format_peer_id(peer_id: Any) -> str:
    to_base58 = getattr(peer_id, "to_base58", None)
    if callable(to_base58):
        try:
            return to_base58()
        except Exception:
            pass
    return str(peer_id)


def _update_from_response(result: Dict[str, Any], response: Any) -> None:
    result["prove_mode"] = None
    result["meta"] = None
    meta_bytes = getattr(response, "meta", b"") or b""
    if meta_bytes:
        try:
            result["meta"] = cbor2.loads(meta_bytes)
            result["prove_mode"] = result["meta"].get("prove_mode")
        except Exception:
            result["meta"] = None


def _error_result(statement: str, peer_id: str, message: str) -> Dict[str, Any]:
    return {
        "backend": "snark-network",
        "statement": _STATEMENT_LABELS.get(statement, statement),
        "peer_id": peer_id,
        "peer_addr": None,
        "protocol_id": PROTOCOL_ID,
        "schema_v": SNARK_SCHEMA_V,
        "depth": DEFAULT_MEMBERSHIP_DEPTH if statement == "membership" else 0,
        "verified": False,
        "error": message,
        "verify_ms": None,
        "exchange_ms": None,
        "asset_source": None,
    }


def _hash_file(path: Any) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    return hashlib.sha256(data).hexdigest()


def _build_summary(
    peer_addr: Optional[str],
    statements: Iterable[str],
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    summary_items = []
    for item in results:
        summary_items.append(
            {
                "statement": item.get("statement"),
                "schema_v": item.get("schema_v"),
                "depth": item.get("depth"),
                "prove_mode": item.get("prove_mode"),
                "verified": item.get("verified"),
                "verify_ms": item.get("verify_ms"),
                "exchange_ms": item.get("exchange_ms"),
                "asset_source": item.get("asset_source"),
            }
        )
    if not summary_items:
        for statement in statements:
            depth = DEFAULT_MEMBERSHIP_DEPTH if statement == "membership" else 0
            summary_items.append(
                {
                    "statement": _STATEMENT_LABELS.get(statement, statement),
                    "schema_v": SNARK_SCHEMA_V,
                    "depth": depth,
                    "prove_mode": None,
                    "verified": None,
                    "verify_ms": None,
                    "exchange_ms": None,
                    "asset_source": None,
                }
            )
    return {
        "protocol_id": PROTOCOL_ID,
        "peer_multiaddr": peer_addr,
        "statements": summary_items,
    }
