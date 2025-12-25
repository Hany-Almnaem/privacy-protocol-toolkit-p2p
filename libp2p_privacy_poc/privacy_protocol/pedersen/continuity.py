"""
Identity continuity proof without disclosure.

Proves: "Two commitments share the same hidden identity scalar"
without revealing the identity or the blinding factors.

This enables proving continuity across sessions while maintaining privacy.
"""

from typing import Tuple
import hashlib

from petlib.ec import EcPt
from petlib.bn import Bn

from ..types import ZKProof, ZKProofType
from ..statements import StatementType
from ..security import RandomnessSource
from .commitments import get_cached_curve_params

# Secp256k1 group (match existing params)
_params = get_cached_curve_params()
group = _params.group
g = _params.G
h = _params.H
order = _params.group.order()

# Domain separator for continuity
DOMAIN_CONTINUITY_CHALLENGE = b"CONTINUITY_CHALLENGE_V1"

_RNG = RandomnessSource()


def _to_bn(value: Bn | int) -> Bn:
    if isinstance(value, Bn):
        return value
    if isinstance(value, int):
        return Bn.from_decimal(str(value))
    raise TypeError(f"Expected Bn or int, got {type(value)}")


def _bn_to_fixed_bytes(value: Bn, length: int = 32) -> bytes:
    return value.binary().rjust(length, b"\x00")


def get_random_scalar_mod_order() -> int:
    return _RNG.get_random_scalar_mod_order()


def generate_continuity_proof(
    identity_scalar: Bn,
    blinding_1: Bn,
    blinding_2: Bn,
    ctx_hash: bytes,
    domain_sep: bytes = b"CONTINUITY_PROOF_V1",
) -> ZKProof:
    """
    Generate identity continuity proof.

    Args:
        identity_scalar: Shared identity scalar (id)
        blinding_1: Blinding for first commitment (r1)
        blinding_2: Blinding for second commitment (r2)
        ctx_hash: Context hash (32 bytes)
        domain_sep: Domain separator

    Returns:
        ZKProof with continuity statement

    Protocol (Two-equation Schnorr):
        Given: C1 = id*G + r1*H, C2 = id*G + r2*H
        Prove: same `id` in both without revealing id, r1, or r2

        1. Compute commitments C1, C2
        2. Generate random nonces: k_id, k_1, k_2
        3. Compute A1 = k_id*G + k_1*H, A2 = k_id*G + k_2*H
           (same k_id for both, different k_i for blinding)
        4. Challenge: c = H(domain_sep || C1 || C2 || A1 || A2 || ctx_hash)
        5. Responses:
           z_id = k_id + c*id
           z_1 = k_1 + c*r1
           z_2 = k_2 + c*r2

        Verification:
           z_id*G + z_1*H == A1 + c*C1
           z_id*G + z_2*H == A2 + c*C2
           (same z_id in both equations proves same id)
    """
    identity_scalar_bn = _to_bn(identity_scalar)
    blinding_1_bn = _to_bn(blinding_1)
    blinding_2_bn = _to_bn(blinding_2)

    # Step 1: Compute commitments
    C1 = (identity_scalar_bn * g) + (blinding_1_bn * h)
    C2 = (identity_scalar_bn * g) + (blinding_2_bn * h)
    C1_bytes = C1.export()
    C2_bytes = C2.export()

    # Step 2-3: Generate nonces and compute A1, A2
    k_id = get_random_scalar_mod_order()
    k_1 = get_random_scalar_mod_order()
    k_2 = get_random_scalar_mod_order()

    while k_id == 0:
        k_id = get_random_scalar_mod_order()
    while k_1 == 0:
        k_1 = get_random_scalar_mod_order()
    while k_2 == 0:
        k_2 = get_random_scalar_mod_order()

    k_id_bn = _to_bn(k_id)
    k_1_bn = _to_bn(k_1)
    k_2_bn = _to_bn(k_2)

    A1 = (k_id_bn * g) + (k_1_bn * h)
    A2 = (k_id_bn * g) + (k_2_bn * h)
    A1_bytes = A1.export()
    A2_bytes = A2.export()

    # Step 4: Challenge computation
    challenge_input = (
        DOMAIN_CONTINUITY_CHALLENGE
        + C1_bytes
        + C2_bytes
        + A1_bytes
        + A2_bytes
        + ctx_hash
    )
    challenge_hash = hashlib.sha256(challenge_input).digest()
    c = Bn.from_binary(challenge_hash) % order

    # Step 5: Compute responses
    z_id = (k_id_bn + c * identity_scalar_bn) % order
    z_1 = (k_1_bn + c * blinding_1_bn) % order
    z_2 = (k_2_bn + c * blinding_2_bn) % order

    # Build ZKProof
    commitment_combined = A1_bytes + A2_bytes
    response_combined = (
        _bn_to_fixed_bytes(z_id)
        + _bn_to_fixed_bytes(z_1)
        + _bn_to_fixed_bytes(z_2)
    )

    public_inputs = {
        "statement_type": StatementType.IDENTITY_CONTINUITY.value,
        "statement_version": 1,
        "commitment_1": C1_bytes,
        "commitment_2": C2_bytes,
        "ctx_hash": ctx_hash,
        "domain_sep": domain_sep,
    }

    proof = ZKProof(
        proof_type=ZKProofType.PEDERSEN_OPENING,
        commitment=commitment_combined,
        challenge=_bn_to_fixed_bytes(c),
        response=response_combined,
        public_inputs=public_inputs,
        timestamp=0.0,
    )

    return proof


def verify_continuity_proof(proof: ZKProof) -> bool:
    """
    Verify identity continuity proof.

    Args:
        proof: ZKProof with continuity statement

    Returns:
        True if proof is valid, False otherwise

    Verification steps:
        1. Validate statement metadata
        2. Extract public inputs (C1, C2, ctx_hash)
        3. Extract A1, A2 from commitment field
        4. Extract z_id, z_1, z_2 from response field
        5. Verify first equation: z_id*G + z_1*H == A1 + c*C1
        6. Verify second equation: z_id*G + z_2*H == A2 + c*C2
        7. Verify challenge binding to both commitments
    """
    try:
        # Step 1: Validate metadata
        proof.validate_statement_metadata()

        if proof.get_statement_type() != StatementType.IDENTITY_CONTINUITY.value:
            return False

        # Step 2: Extract public inputs
        public_inputs = proof.public_inputs
        C1_bytes = public_inputs["commitment_1"]
        C2_bytes = public_inputs["commitment_2"]
        ctx_hash = public_inputs["ctx_hash"]
        _ = public_inputs["domain_sep"]

        C1 = EcPt.from_binary(C1_bytes, group)
        C2 = EcPt.from_binary(C2_bytes, group)

        # Step 3: Extract A1, A2
        commitment_combined = proof.commitment
        if not isinstance(commitment_combined, (bytes, bytearray)):
            return False
        if len(commitment_combined) != 66:  # 33 + 33
            return False
        A1_bytes = commitment_combined[:33]
        A2_bytes = commitment_combined[33:]
        A1 = EcPt.from_binary(A1_bytes, group)
        A2 = EcPt.from_binary(A2_bytes, group)

        # Extract challenge
        if not isinstance(proof.challenge, (bytes, bytearray)):
            return False
        if len(proof.challenge) != 32:
            return False
        c = Bn.from_binary(proof.challenge)

        # Step 4: Extract z_id, z_1, z_2
        response_combined = proof.response
        if not isinstance(response_combined, (bytes, bytearray)):
            return False
        if len(response_combined) != 96:  # 32 + 32 + 32
            return False
        z_id = Bn.from_binary(response_combined[:32])
        z_1 = Bn.from_binary(response_combined[32:64])
        z_2 = Bn.from_binary(response_combined[64:96])

        # Step 5: Verify first equation
        left_1 = (z_id * g) + (z_1 * h)
        right_1 = A1 + (c * C1)
        if left_1 != right_1:
            return False

        # Step 6: Verify second equation
        left_2 = (z_id * g) + (z_2 * h)
        right_2 = A2 + (c * C2)
        if left_2 != right_2:
            return False

        # Step 7: Verify challenge binding
        challenge_input = (
            DOMAIN_CONTINUITY_CHALLENGE
            + C1_bytes
            + C2_bytes
            + A1_bytes
            + A2_bytes
            + ctx_hash
        )
        expected_challenge_hash = hashlib.sha256(challenge_input).digest()
        expected_c = Bn.from_binary(expected_challenge_hash) % order

        if c != expected_c:
            return False

        return True

    except Exception:
        return False


def extract_identity_from_two_proofs(
    proof1: ZKProof,
    proof2: ZKProof,
) -> Tuple[bool, Bn]:
    """
    Attempt to extract identity scalar using two valid proofs (special soundness).

    This demonstrates the proof's extractability property:
    If an adversary can produce two valid proofs with different challenges
    for the same commitments, we can extract the witness.

    Args:
        proof1: First valid continuity proof
        proof2: Second valid continuity proof (same C1, C2, different challenge)

    Returns:
        (success: bool, identity_scalar: Bn)

    Algorithm:
        Given two valid proofs with challenges c1, c2:
        - z_id1 = k_id + c1*id
        - z_id2 = k_id + c2*id  (same k_id if same randomness)

        Solve for id:
        z_id1 - z_id2 = (c1 - c2)*id
        id = (z_id1 - z_id2) / (c1 - c2)  [mod order]

    Note: This only works if both proofs used the same nonces.
    """
    try:
        if not (verify_continuity_proof(proof1) and verify_continuity_proof(proof2)):
            return False, Bn.from_num(0)

        if (
            proof1.public_inputs["commitment_1"]
            != proof2.public_inputs["commitment_1"]
            or proof1.public_inputs["commitment_2"]
            != proof2.public_inputs["commitment_2"]
        ):
            return False, Bn.from_num(0)

        if proof1.commitment != proof2.commitment:
            return False, Bn.from_num(0)

        c1 = Bn.from_binary(proof1.challenge)
        c2 = Bn.from_binary(proof2.challenge)

        if c1 == c2:
            return False, Bn.from_num(0)

        if proof1.response is None or proof2.response is None:
            return False, Bn.from_num(0)
        if len(proof1.response) < 32 or len(proof2.response) < 32:
            return False, Bn.from_num(0)

        z_id1 = Bn.from_binary(proof1.response[:32])
        z_id2 = Bn.from_binary(proof2.response[:32])

        numerator = (z_id1 - z_id2) % order
        denominator = (c1 - c2) % order

        if denominator == 0:
            return False, Bn.from_num(0)

        identity_scalar = (numerator * denominator.mod_inverse(order)) % order

        return True, identity_scalar

    except Exception:
        return False, Bn.from_num(0)
