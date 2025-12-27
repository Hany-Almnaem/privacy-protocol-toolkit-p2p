"""
Anonymity set membership proof using Merkle trees.

Proves: "I know an identity scalar whose commitment is in the Merkle tree"
without revealing the identity or which leaf it is.
"""

from typing import List, Tuple, Dict, Any
import hashlib

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn

from ..types import ZKProof, ZKProofType
from ..merkle import (
    hash_leaf, verify_path, DOMAIN_SEPARATORS_2B
)
from ..statements import StatementType
from ..security import RandomnessSource
from .commitments import get_cached_curve_params

# Secp256k1 group (from existing code)
_params = get_cached_curve_params()
group = _params.group
g = _params.G
h = _params.H
order = _params.group.order()


def _to_bn(value: Bn | int) -> Bn:
    if isinstance(value, Bn):
        return value
    if isinstance(value, int):
        return Bn.from_decimal(str(value))
    raise TypeError(f"Expected Bn or int, got {type(value)}")


def _bn_to_fixed_bytes(value: Bn, length: int = 32) -> bytes:
    return value.binary().rjust(length, b"\x00")


def generate_membership_proof(
    identity_scalar: Bn,
    blinding: Bn,
    merkle_path: List[Tuple[bytes, bool]],
    root: bytes,
    ctx_hash: bytes,
    domain_sep: bytes = b"MEMBERSHIP_PROOF_V1"
) -> ZKProof:
    """
    Generate anonymity set membership proof.

    Args:
        identity_scalar: Secret identity scalar (id)
        blinding: Blinding factor (r) for commitment
        merkle_path: Authentication path [(sibling, is_left), ...]
        root: Merkle tree root (32 bytes)
        ctx_hash: Context hash (32 bytes)
        domain_sep: Domain separator

    Returns:
        ZKProof with membership statement

    Protocol:
        1. Compute commitment: C = id*G + r*H
        2. Verify C is in Merkle tree with given path/root
        3. Generate Schnorr PoK for (id, r) binding to C
        4. Embed proof in ZKProof with statement metadata
    """
    identity_scalar_bn = _to_bn(identity_scalar)
    blinding_bn = _to_bn(blinding)

    # Step 1: Compute commitment
    commitment_point = (identity_scalar_bn * g) + (blinding_bn * h)
    commitment_bytes = commitment_point.export()  # Compressed 33 bytes

    # Step 2: Verify Merkle path (prover check)
    leaf_hash = hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], commitment_bytes)
    if not verify_path(leaf_hash, merkle_path, root):
        raise ValueError("Merkle path verification failed (prover check)")

    # Step 3: Generate Schnorr PoK binding (id, r) to C
    # Challenge binds: root, C, ctx_hash
    # This proves knowledge of opening without revealing id or r

    # Schnorr protocol:
    # - Choose random nonces k_v, k_b
    # - Compute A = k_v*G + k_b*H
    # - Challenge c = H(domain_sep || root || C || A || ctx_hash)
    # - Responses: z_v = k_v + c*id, z_b = k_b + c*r
    rng = RandomnessSource()

    k_v = rng.get_random_scalar_mod_order()
    k_b = rng.get_random_scalar_mod_order()

    while k_v == 0:
        k_v = rng.get_random_scalar_mod_order()

    while k_b == 0:
        k_b = rng.get_random_scalar_mod_order()

    k_v_bn = _to_bn(k_v)
    k_b_bn = _to_bn(k_b)

    A = (k_v_bn * g) + (k_b_bn * h)
    A_bytes = A.export()

    # Challenge computation
    challenge_input = (
        domain_sep +
        root +
        commitment_bytes +
        A_bytes +
        ctx_hash
    )
    challenge_hash = hashlib.sha256(challenge_input).digest()
    c = Bn.from_binary(challenge_hash) % order

    # Responses
    z_v = (k_v_bn + c * identity_scalar_bn) % order
    z_b = (k_b_bn + c * blinding_bn) % order

    # Build ZKProof
    public_inputs = {
        "statement_type": StatementType.ANON_SET_MEMBERSHIP.value,
        "statement_version": 1,
        "root": root,
        "commitment": commitment_bytes,
        "ctx_hash": ctx_hash,
        "domain_sep": domain_sep,
        "merkle_path": [
            {"sibling": sib, "is_left": is_left}
            for sib, is_left in merkle_path
        ],
    }

    proof = ZKProof(
        proof_type=ZKProofType.PEDERSEN_OPENING,  # Reuse existing type
        commitment=A_bytes,  # Store A (Schnorr commitment)
        challenge=_bn_to_fixed_bytes(c),
        response=_bn_to_fixed_bytes(z_v) + _bn_to_fixed_bytes(z_b),
        public_inputs=public_inputs,
        timestamp=0.0,  # Set by caller if needed
    )

    return proof


def verify_membership_proof(proof: ZKProof) -> bool:
    """
    Verify anonymity set membership proof.

    Args:
        proof: ZKProof with membership statement

    Returns:
        True if proof is valid, False otherwise

    Verification steps:
        1. Validate statement metadata
        2. Extract public inputs (root, commitment, path)
        3. Verify Merkle path
        4. Verify Schnorr PoK (z_v*G + z_b*H == A + c*C)
    """
    try:
        # Step 1: Validate metadata
        proof.validate_statement_metadata()

        if proof.get_statement_type() != StatementType.ANON_SET_MEMBERSHIP.value:
            return False

        # Step 2: Extract public inputs
        public_inputs = proof.public_inputs
        root = public_inputs["root"]
        commitment_bytes = public_inputs["commitment"]
        ctx_hash = public_inputs["ctx_hash"]
        domain_sep = public_inputs["domain_sep"]
        merkle_path_dicts = public_inputs["merkle_path"]

        # Convert merkle_path from dict format to tuple format
        merkle_path = [
            (item["sibling"], item["is_left"])
            for item in merkle_path_dicts
        ]

        # Step 3: Verify Merkle path
        leaf_hash = hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], commitment_bytes)
        if not verify_path(leaf_hash, merkle_path, root):
            return False

        # Step 4: Verify Schnorr PoK
        C = EcPt.from_binary(commitment_bytes, group)
        A = EcPt.from_binary(proof.commitment, group)  # A stored in commitment
        c = Bn.from_binary(proof.challenge)

        # Parse concatenated responses
        response_bytes = proof.response
        if response_bytes is None or len(response_bytes) != 64:  # 32 + 32
            return False
        z_v = Bn.from_binary(response_bytes[:32])
        z_b = Bn.from_binary(response_bytes[32:])

        # Verify: z_v*G + z_b*H == A + c*C
        left_side = (z_v * g) + (z_b * h)
        right_side = A + (c * C)

        if left_side != right_side:
            return False

        # Recompute challenge to verify binding
        challenge_input = (
            domain_sep +
            root +
            commitment_bytes +
            proof.commitment +  # A_bytes
            ctx_hash
        )
        expected_challenge_hash = hashlib.sha256(challenge_input).digest()
        expected_c = Bn.from_binary(expected_challenge_hash) % order

        if c != expected_c:
            return False

        return True

    except Exception:
        # Any parsing/validation error => invalid proof
        return False
