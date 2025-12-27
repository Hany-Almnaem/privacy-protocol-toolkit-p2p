# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

DOMAIN_SEPARATORS = {
    "peer_id_scalar": b"LIBP2P_PRIVACY_PEER_ID_SCALAR_V1",
    "commitment": b"PEDERSEN_COMMITMENT_V1",
    "schnorr_challenge": b"SCHNORR_CHALLENGE_V1",
}

DOMAIN_SEPARATORS_2B = {
    "merkle_leaf": b"MERKLE_LEAF_V1",
    "merkle_node": b"MERKLE_NODE_V1",
    "membership_challenge": b"MEMBERSHIP_CHALLENGE_V1",
    "unlinkability_tag": b"UNLINKABILITY_TAG_V1",
    "continuity_challenge": b"CONTINUITY_CHALLENGE_V1",
}

VECTOR_FILE = Path(__file__).with_name("phase2b_vectors.json")


def load_vectors(path: Path = VECTOR_FILE) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def compute_expected(vectors: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    identity = vectors["identity_derivation"]
    merkle = vectors["merkle_leaf"]
    membership = vectors["membership_challenge"]

    peer_id = _require_string(identity.get("peer_id"), "identity_derivation.peer_id")
    commitment_bytes = _require_hex(merkle.get("commitment_hex"), 66, "merkle_leaf.commitment_hex")
    root_bytes = _require_hex(membership.get("root_hex"), 64, "membership_challenge.root_hex")
    membership_commitment = _require_hex(
        membership.get("commitment_hex"), 66, "membership_challenge.commitment_hex"
    )
    ctx_hash_bytes = _require_hex(
        membership.get("ctx_hash_hex"), 64, "membership_challenge.ctx_hash_hex"
    )

    identity_digest = hashlib.sha256(
        DOMAIN_SEPARATORS["peer_id_scalar"] + peer_id.encode("utf-8")
    ).digest()
    identity_scalar_hex = _hash_to_scalar_hex(identity_digest)

    leaf_digest = hashlib.sha256(
        DOMAIN_SEPARATORS_2B["merkle_leaf"] + commitment_bytes
    ).digest()
    leaf_hex = leaf_digest.hex()

    challenge_digest = hashlib.sha256(
        DOMAIN_SEPARATORS_2B["membership_challenge"]
        + root_bytes
        + membership_commitment
        + ctx_hash_bytes
    ).digest()
    challenge_hex = _hash_to_scalar_hex(challenge_digest)

    return {
        "identity_derivation": {"expected_scalar_hex": identity_scalar_hex},
        "merkle_leaf": {"expected_leaf_hex": leaf_hex},
        "membership_challenge": {"expected_challenge_hex": challenge_hex},
    }


def validate_vectors(data: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if data.get("version") != "2B.0":
        errors.append("version must be 2B.0")
    if data.get("curve") != "secp256k1":
        errors.append("curve must be secp256k1")
    if data.get("hash") != "SHA-256":
        errors.append("hash must be SHA-256")

    vectors = data.get("vectors")
    if not isinstance(vectors, dict):
        errors.append("vectors must be a dict")
        return errors

    try:
        expected = compute_expected(vectors)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(str(exc))
        return errors

    identity = vectors.get("identity_derivation", {})
    if identity.get("expected_scalar_hex") != expected["identity_derivation"]["expected_scalar_hex"]:
        errors.append("identity_derivation.expected_scalar_hex mismatch")

    merkle = vectors.get("merkle_leaf", {})
    if merkle.get("expected_leaf_hex") != expected["merkle_leaf"]["expected_leaf_hex"]:
        errors.append("merkle_leaf.expected_leaf_hex mismatch")

    membership = vectors.get("membership_challenge", {})
    if (
        membership.get("expected_challenge_hex")
        != expected["membership_challenge"]["expected_challenge_hex"]
    ):
        errors.append("membership_challenge.expected_challenge_hex mismatch")

    return errors


def _hash_to_scalar_hex(digest: bytes) -> str:
    scalar = int.from_bytes(digest, "big") % GROUP_ORDER
    return scalar.to_bytes(32, "big").hex()


def _require_hex(value: Any, expected_len: int, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a hex string")
    if len(value) != expected_len:
        raise ValueError(f"{field_name} must be {expected_len} hex chars")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid hex") from exc
    if len(raw) * 2 != expected_len:
        raise ValueError(f"{field_name} has invalid byte length")
    return raw


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value
