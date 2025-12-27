"""
Session unlinkability proof.

Proves: "This session commitment is correctly formed from my identity"
without revealing the identity or linking to other sessions.

Key property: Same identity + different context -> different session tag
"""

import hashlib

from petlib.ec import EcPt
from petlib.bn import Bn

from ..types import ZKProof, ZKProofType
from ..statements import StatementType
from ..security import RandomnessSource
from .commitments import get_cached_curve_params

# Secp256k1 group (match membership.py)
_params = get_cached_curve_params()
group = _params.group
g = _params.G
h = _params.H
order = _params.group.order()

# Domain separators for unlinkability
DOMAIN_UNLINKABILITY_TAG = b"UNLINKABILITY_TAG_V1"
DOMAIN_UNLINKABILITY_CHALLENGE = b"UNLINKABILITY_CHALLENGE_V1"


def _to_bn(value: Bn | int) -> Bn:
    if isinstance(value, Bn):
        return value
    if isinstance(value, int):
        return Bn.from_decimal(str(value))
    raise TypeError(f"Expected Bn or int, got {type(value)}")


def _bn_to_fixed_bytes(value: Bn, length: int = 32) -> bytes:
    return value.binary().rjust(length, b"\x00")


def compute_session_tag(
    commitment_bytes: bytes,
    ctx_hash: bytes
) -> bytes:
    """
    Compute deterministic session tag.

    Args:
        commitment_bytes: Serialized commitment point (33 bytes)
        ctx_hash: Context hash (32 bytes)

    Returns:
        32-byte session tag

    Note:
        Tag is deterministic given commitment and context.
        Same identity with different context -> different tag (via fresh blinding).
    """
    tag_input = DOMAIN_UNLINKABILITY_TAG + ctx_hash + commitment_bytes
    return hashlib.sha256(tag_input).digest()


def generate_unlinkability_proof(
    identity_scalar: Bn,
    blinding: Bn,
    ctx_hash: bytes,
    domain_sep: bytes = b"UNLINKABILITY_PROOF_V1"
) -> ZKProof:
    """
    Generate session unlinkability proof.

    Args:
        identity_scalar: Secret identity scalar (id)
        blinding: Fresh blinding factor for this session (r)
        ctx_hash: Context hash (32 bytes) - binds to session/topic
        domain_sep: Domain separator

    Returns:
        ZKProof with unlinkability statement

    Protocol:
        1. Compute commitment: C = id*G + r*H (fresh r per session)
        2. Compute session tag: tag = H(domain || ctx_hash || C)
        3. Generate Schnorr PoK for (id, r) binding to C and ctx_hash
        4. Tag is public, commitment is public, but id remains hidden

    Unlinkability property:
        - Given (tag1, C1, ctx1) and (tag2, C2, ctx2):
        - If ctx1 != ctx2, then tag1 != tag2 (deterministic tag computation)
        - Cannot determine if same identity used (random blinding breaks linkage)
    """
    identity_scalar_bn = _to_bn(identity_scalar)
    blinding_bn = _to_bn(blinding)

    # Step 1: Compute commitment
    commitment_point = (identity_scalar_bn * g) + (blinding_bn * h)
    commitment_bytes = commitment_point.export()

    # Step 2: Compute session tag
    session_tag = compute_session_tag(commitment_bytes, ctx_hash)

    # Step 3: Generate Schnorr PoK binding (id, r) to C and ctx_hash
    # Challenge binds: tag, C, ctx_hash
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
        DOMAIN_UNLINKABILITY_CHALLENGE +
        session_tag +
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
        "statement_type": StatementType.SESSION_UNLINKABILITY.value,
        "statement_version": 1,
        "tag": session_tag,
        "commitment": commitment_bytes,
        "ctx_hash": ctx_hash,
        "domain_sep": domain_sep,
    }

    proof = ZKProof(
        proof_type=ZKProofType.PEDERSEN_OPENING,
        commitment=A_bytes,
        challenge=_bn_to_fixed_bytes(c),
        response=_bn_to_fixed_bytes(z_v) + _bn_to_fixed_bytes(z_b),
        public_inputs=public_inputs,
        timestamp=0.0,
    )

    return proof


def verify_unlinkability_proof(proof: ZKProof) -> bool:
    """
    Verify session unlinkability proof.

    Args:
        proof: ZKProof with unlinkability statement

    Returns:
        True if proof is valid, False otherwise

    Verification steps:
        1. Validate statement metadata
        2. Extract public inputs (tag, commitment, ctx_hash)
        3. Recompute tag from commitment + ctx_hash
        4. Verify Schnorr PoK (z_v*G + z_b*H == A + c*C)
        5. Verify challenge binding to tag and context
    """
    try:
        # Step 1: Validate metadata
        proof.validate_statement_metadata()

        if proof.get_statement_type() != StatementType.SESSION_UNLINKABILITY.value:
            return False

        # Step 2: Extract public inputs
        public_inputs = proof.public_inputs
        tag = public_inputs["tag"]
        commitment_bytes = public_inputs["commitment"]
        ctx_hash = public_inputs["ctx_hash"]
        _ = public_inputs["domain_sep"]

        # Step 3: Verify tag computation
        expected_tag = compute_session_tag(commitment_bytes, ctx_hash)
        if tag != expected_tag:
            return False

        # Step 4: Verify Schnorr PoK
        C = EcPt.from_binary(commitment_bytes, group)
        A = EcPt.from_binary(proof.commitment, group)
        c = Bn.from_binary(proof.challenge)

        # Parse responses
        response_bytes = proof.response
        if response_bytes is None or len(response_bytes) != 64:
            return False
        z_v = Bn.from_binary(response_bytes[:32])
        z_b = Bn.from_binary(response_bytes[32:])

        # Verify: z_v*G + z_b*H == A + c*C
        left_side = (z_v * g) + (z_b * h)
        right_side = A + (c * C)

        if left_side != right_side:
            return False

        # Step 5: Recompute challenge to verify binding
        challenge_input = (
            DOMAIN_UNLINKABILITY_CHALLENGE +
            tag +
            commitment_bytes +
            proof.commitment +
            ctx_hash
        )
        expected_challenge_hash = hashlib.sha256(challenge_input).digest()
        expected_c = Bn.from_binary(expected_challenge_hash) % order

        if c != expected_c:
            return False

        return True

    except Exception:
        return False


def check_unlinkability(
    proof1: ZKProof,
    proof2: ZKProof
) -> bool:
    """
    Check if two proofs demonstrate unlinkability.

    Args:
        proof1: First session proof
        proof2: Second session proof

    Returns:
        True if sessions are properly unlinkable

    Criteria:
        - Different contexts -> different tags (required)
        - Different commitments (expected with fresh blinding)
        - Same context -> same tag (should fail unlinkability)
    """
    if not (verify_unlinkability_proof(proof1) and verify_unlinkability_proof(proof2)):
        return False

    ctx1 = proof1.public_inputs["ctx_hash"]
    ctx2 = proof2.public_inputs["ctx_hash"]
    tag1 = proof1.public_inputs["tag"]
    tag2 = proof2.public_inputs["tag"]

    # Different contexts MUST produce different tags
    if ctx1 != ctx2:
        return tag1 != tag2

    # Same context SHOULD produce same tag (deterministic)
    # This is NOT unlinkable - it's a failure mode
    return tag1 == tag2
