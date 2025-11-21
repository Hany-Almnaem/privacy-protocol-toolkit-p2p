"""
⚠️ DRAFT — requires crypto review before production use

Schnorr Proof of Knowledge for Pedersen Commitments.

This is a PROTOTYPE implementation for testing and validation.
DO NOT use in production without security audit.

Schnorr Proof of Knowledge (PoK):
    Proves knowledge of commitment opening (value, blinding) without revealing it.
    
    Protocol (Non-Interactive via Fiat-Shamir):
        Prover knows (value, blinding) such that C = value*G + blinding*H
        
        1. Generate random nonces: r_v, r_b ← Z_q
        2. Compute announcement: A = r_v*G + r_b*H
        3. Compute challenge: c = Hash(G, H, C, A, context) mod q
        4. Compute responses: z_v = (r_v + c*value) mod q
                              z_b = (r_b + c*blinding) mod q
        5. Proof = (A, c, z_v, z_b)
        
        Verifier checks:
        1. Recompute c' = Hash(G, H, C, A, context) mod q
        2. Verify c' = c (constant-time comparison)
        3. Verify z_v*G + z_b*H = A + c*C

Security Properties:
    - Completeness: Honest prover always succeeds
    - Soundness: Malicious prover cannot forge valid proof
    - Zero-Knowledge: Proof reveals no information about value/blinding
    - Special Soundness: Two proofs with same A, different c → witness extraction

Security Requirements:
    1. Nonces MUST be random and unique per proof (nonce reuse breaks ZK)
    2. Challenge MUST use length-prefixed hashing (prevents collisions)
    3. All scalar operations MUST be modulo GROUP_ORDER (prevents overflow)
    4. Challenge verification MUST be constant-time (prevents timing attacks)
    5. Input validation before all computations

Implementation Details:
    - Curve: secp256k1 (NID 714)
    - Library: petlib 0.0.45+
    - Challenge: SHA-256 (32 bytes) reduced modulo GROUP_ORDER
    - Proof size: ~129 bytes (A: 33, c: 32, z_v: 32, z_b: 32)
"""

from typing import Dict, Optional
import hashlib

try:
    from petlib.ec import EcPt
    from petlib.bn import Bn
except ImportError:
    raise ImportError(
        "petlib is required for Schnorr proofs. "
        "Install with: pip install petlib"
    )

from .commitments import CurveParameters, setup_curve
from ..security import RandomnessSource, constant_time_compare
from ..config import GROUP_ORDER, POINT_SIZE_BYTES
from ..exceptions import ProofGenerationError, ProofVerificationError


# ============================================================================
# SCHNORR PROOF GENERATION
# ============================================================================


def generate_schnorr_pok(
    commitment: bytes,
    value: int,
    blinding: int,
    context: bytes,
    params: Optional[CurveParameters] = None,
    randomness_source: Optional[RandomnessSource] = None
) -> Dict[str, bytes]:
    """
    Generate Schnorr proof of knowledge for commitment opening.
    
    ⚠️ SECURITY CRITICAL
    
    This proves knowledge of (value, blinding) such that:
        commitment = value*G + blinding*H
    
    Without revealing value or blinding (zero-knowledge property).
    
    Protocol (Fiat-Shamir):
    1. Generate random nonces r_v, r_b (MUST be unique per proof)
    2. Compute announcement A = r_v*G + r_b*H
    3. Compute challenge c = Hash(G, H, C, A, context) mod q
    4. Compute responses z_v = (r_v + c*value) mod q
                         z_b = (r_b + c*blinding) mod q
    
    Args:
        commitment: Commitment to prove knowledge of (33 bytes)
        value: Committed value (witness, kept secret, must be in [0, GROUP_ORDER))
        blinding: Blinding factor (witness, kept secret, must be in [0, GROUP_ORDER))
        context: Additional context for challenge binding
        params: Curve parameters (initialized if None)
        randomness_source: Source for nonce generation (created if None)
    
    Returns:
        Dict with proof components:
            - 'A': Announcement point (33 bytes)
            - 'c': Challenge (32 bytes)
            - 'z_v': Response for value (32 bytes)
            - 'z_b': Response for blinding (32 bytes)
        Total proof size: ~129 bytes
    
    Raises:
        ValueError: If inputs are invalid (type, range, format)
        ProofGenerationError: If proof generation fails
    
    Example:
        >>> from .commitments import commit
        >>> from ..types import ProofContext
        >>> params = setup_curve()
        >>> commitment, blinding = commit(42, params=params)
        >>> ctx = ProofContext(peer_id="QmTest")
        >>> proof = generate_schnorr_pok(
        ...     commitment=commitment,
        ...     value=42,
        ...     blinding=blinding,
        ...     context=ctx.to_bytes(),
        ...     params=params
        ... )
        >>> assert 'A' in proof and 'c' in proof
        >>> assert len(proof['A']) == 33
        >>> assert len(proof['c']) == 32
    
    Security Notes:
        - Nonces MUST be random and unique per proof
        - Nonce reuse breaks zero-knowledge (allows witness extraction)
        - Challenge binds proof to context and commitment
        - All arithmetic modulo GROUP_ORDER
        - Proof reveals no information about value/blinding
    """
    # ========================================================================
    # Input Validation
    # ========================================================================
    
    # Validate commitment format
    if not isinstance(commitment, bytes):
        raise TypeError(f"commitment must be bytes, got {type(commitment)}")
    
    if len(commitment) != POINT_SIZE_BYTES:
        raise ValueError(
            f"Invalid commitment size: expected {POINT_SIZE_BYTES} bytes, "
            f"got {len(commitment)}"
        )
    
    # Validate value and blinding are integers in valid range
    if not isinstance(value, int):
        raise TypeError(f"value must be int, got {type(value)}")
    
    if not isinstance(blinding, int):
        raise TypeError(f"blinding must be int, got {type(blinding)}")
    
    if not (0 <= value < GROUP_ORDER):
        raise ValueError(
            f"value must be in [0, GROUP_ORDER), got {value}"
        )
    
    if not (0 <= blinding < GROUP_ORDER):
        raise ValueError(
            f"blinding must be in [0, GROUP_ORDER), got {blinding}"
        )
    
    # Validate context
    if not isinstance(context, bytes):
        raise TypeError(f"context must be bytes, got {type(context)}")
    
    # ========================================================================
    # Initialize Parameters
    # ========================================================================
    
    # Initialize curve parameters if not provided
    if params is None:
        params = setup_curve()
    
    # Initialize randomness source if not provided (fork-safe)
    if randomness_source is None:
        randomness_source = RandomnessSource()
    
    try:
        # ====================================================================
        # Generate Nonces (CRITICAL: Must be unique per proof)
        # ====================================================================
        
        # Generate random nonces for value and blinding
        # These MUST be cryptographically random and unique per proof
        # Nonce reuse allows witness extraction!
        r_v = randomness_source.get_random_scalar_mod_order()
        r_b = randomness_source.get_random_scalar_mod_order()
        
        # Validate nonces are non-zero (zero nonce leaks witness!)
        # If r_v = 0: z_v = c*value → value = z_v / c (LEAKED!)
        # If r_b = 0: z_b = c*blinding → blinding = z_b / c (LEAKED!)
        while r_v == 0:
            r_v = randomness_source.get_random_scalar_mod_order()
        
        while r_b == 0:
            r_b = randomness_source.get_random_scalar_mod_order()
        
        # ====================================================================
        # Compute Announcement A = r_v*G + r_b*H
        # ====================================================================
        
        # Convert nonces to petlib Bn for elliptic curve operations
        r_v_bn = Bn.from_decimal(str(r_v))
        r_b_bn = Bn.from_decimal(str(r_b))
        
        # Compute announcement: A = r_v*G + r_b*H
        A = r_v_bn * params.G + r_b_bn * params.H
        
        # Serialize announcement to bytes (compressed point format)
        A_bytes = A.export()
        
        # Validate announcement size
        if len(A_bytes) != POINT_SIZE_BYTES:
            raise ProofGenerationError(
                f"Invalid announcement size: {len(A_bytes)}"
            )
        
        # ====================================================================
        # Compute Challenge c = Hash(G, H, C, A, context) mod q
        # ====================================================================
        
        # Use length-prefixed hashing to prevent collision attacks
        challenge_bytes = _compute_challenge(
            params.G,
            params.H,
            commitment,
            A_bytes,
            context
        )
        
        # Convert challenge to scalar modulo GROUP_ORDER
        c = int.from_bytes(challenge_bytes, 'big') % GROUP_ORDER
        
        # ====================================================================
        # Compute Responses z_v and z_b (CRITICAL: Modulo GROUP_ORDER)
        # ====================================================================
        
        # Response for value: z_v = (r_v + c*value) mod q
        # MUST use modulo to prevent:
        # 1. Integer overflow (c*value can be huge)
        # 2. Information leakage (response size reveals value range)
        # 3. Serialization errors (won't fit in 32 bytes)
        z_v = (r_v + c * value) % GROUP_ORDER
        
        # Response for blinding: z_b = (r_b + c*blinding) mod q
        z_b = (r_b + c * blinding) % GROUP_ORDER
        
        # Validate responses are in valid range
        assert 0 <= z_v < GROUP_ORDER, "z_v out of range"
        assert 0 <= z_b < GROUP_ORDER, "z_b out of range"
        
        # ====================================================================
        # Serialize Proof
        # ====================================================================
        
        # Serialize responses to 32-byte big-endian integers
        z_v_bytes = z_v.to_bytes(32, 'big')
        z_b_bytes = z_b.to_bytes(32, 'big')
        
        # Return proof as dictionary (serializable to CBOR via ZKProof)
        proof = {
            'A': A_bytes,           # Announcement (33 bytes)
            'c': challenge_bytes,   # Challenge (32 bytes)
            'z_v': z_v_bytes,       # Response for value (32 bytes)
            'z_b': z_b_bytes        # Response for blinding (32 bytes)
        }
        
        return proof
        
    except Exception as e:
        # Catch all errors to prevent information leakage through errors
        # Re-raise with generic error message
        raise ProofGenerationError(
            f"Schnorr proof generation failed: {type(e).__name__}"
        ) from e


# ============================================================================
# SCHNORR PROOF VERIFICATION
# ============================================================================


def verify_schnorr_pok(
    commitment: bytes,
    proof: Dict[str, bytes],
    context: bytes,
    params: Optional[CurveParameters] = None
) -> bool:
    """
    Verify Schnorr proof of knowledge for commitment.
    
    ⚠️ SECURITY CRITICAL
    
    Verifies that prover knows (value, blinding) for commitment
    without learning the values.
    
    Verification:
    1. Extract proof components (A, c, z_v, z_b)
    2. Recompute challenge c' = Hash(G, H, C, A, context) mod q
    3. Check c' = c (constant-time comparison)
    4. Check z_v*G + z_b*H = A + c*C (verification equation)
    
    Args:
        commitment: The commitment being verified (33 bytes)
        proof: Proof dict with keys 'A', 'c', 'z_v', 'z_b'
        context: Context (must match proof generation)
        params: Curve parameters (initialized if None)
    
    Returns:
        True if proof is valid, False otherwise
    
    Raises:
        ValueError: If inputs have invalid format
        ProofVerificationError: If verification computation fails
    
    Example:
        >>> from .commitments import commit
        >>> from ..types import ProofContext
        >>> params = setup_curve()
        >>> commitment, blinding = commit(42, params=params)
        >>> ctx = ProofContext(peer_id="QmTest")
        >>> proof = generate_schnorr_pok(commitment, 42, blinding, ctx.to_bytes(), params)
        >>> assert verify_schnorr_pok(commitment, proof, ctx.to_bytes(), params)
        >>> # Wrong context should fail
        >>> wrong_ctx = ProofContext(peer_id="QmWrong")
        >>> assert not verify_schnorr_pok(commitment, proof, wrong_ctx.to_bytes(), params)
    
    Security Notes:
        - Challenge verification uses constant-time comparison
        - Invalid proofs return False (no information leakage)
        - Context binding prevents proof reuse in different contexts
        - All arithmetic modulo GROUP_ORDER
        - Returns False on any cryptographic error
    """
    # ========================================================================
    # Input Validation
    # ========================================================================
    
    try:
        # Validate commitment format
        if not isinstance(commitment, bytes):
            raise ValueError(f"commitment must be bytes, got {type(commitment)}")
        
        if len(commitment) != POINT_SIZE_BYTES:
            raise ValueError(
                f"Invalid commitment size: expected {POINT_SIZE_BYTES} bytes, "
                f"got {len(commitment)}"
            )
        
        # Validate context
        if not isinstance(context, bytes):
            raise ValueError(f"context must be bytes, got {type(context)}")
        
        # Validate proof structure
        if not isinstance(proof, dict):
            raise ValueError(f"proof must be dict, got {type(proof)}")
        
        # Check all required keys present
        required_keys = {'A', 'c', 'z_v', 'z_b'}
        if not required_keys.issubset(proof.keys()):
            missing_keys = required_keys - proof.keys()
            raise ValueError(f"Missing proof keys: {missing_keys}")
        
        # Validate proof component sizes
        if len(proof['A']) != POINT_SIZE_BYTES:
            raise ValueError(
                f"Invalid announcement size: expected {POINT_SIZE_BYTES} bytes, "
                f"got {len(proof['A'])}"
            )
        
        if len(proof['c']) != 32:
            raise ValueError(
                f"Invalid challenge size: expected 32 bytes, got {len(proof['c'])}"
            )
        
        if len(proof['z_v']) != 32:
            raise ValueError(
                f"Invalid z_v size: expected 32 bytes, got {len(proof['z_v'])}"
            )
        
        if len(proof['z_b']) != 32:
            raise ValueError(
                f"Invalid z_b size: expected 32 bytes, got {len(proof['z_b'])}"
            )
        
    except ValueError:
        # Input validation errors - re-raise for debugging
        raise
    
    # ========================================================================
    # Initialize Parameters
    # ========================================================================
    
    # Initialize curve parameters if not provided
    if params is None:
        params = setup_curve()
    
    try:
        # ====================================================================
        # Extract Proof Components
        # ====================================================================
        
        # Deserialize announcement point
        try:
            A = EcPt.from_binary(proof['A'], params.group)
        except Exception:
            # Invalid point encoding
            return False
        
        # Validate announcement point
        if A is None:
            return False
        
        # Validate point is on curve
        if not params.group.check_point(A):
            return False
        
        # Extract challenge
        c_bytes = proof['c']
        
        # Convert challenge to scalar (with modular reduction for safety)
        c = int.from_bytes(c_bytes, 'big') % GROUP_ORDER
        
        # Extract responses
        z_v = int.from_bytes(proof['z_v'], 'big') % GROUP_ORDER
        z_b = int.from_bytes(proof['z_b'], 'big') % GROUP_ORDER
        
        # ====================================================================
        # Recompute Challenge c' = Hash(G, H, C, A, context) mod q
        # ====================================================================
        
        # Use same challenge computation as proof generation
        expected_challenge_bytes = _compute_challenge(
            params.G,
            params.H,
            commitment,
            proof['A'],
            context
        )
        
        # ====================================================================
        # Verify Challenge Matches (CONSTANT-TIME)
        # ====================================================================
        
        # CRITICAL: Must use constant-time comparison to prevent timing attacks
        # Timing attacks can reveal if challenges match byte-by-byte
        if not constant_time_compare(c_bytes, expected_challenge_bytes):
            # Challenge mismatch - proof is invalid or for different context
            return False
        
        # ====================================================================
        # Verify Verification Equation: z_v*G + z_b*H = A + c*C
        # ====================================================================
        
        # Deserialize commitment point
        try:
            C = EcPt.from_binary(commitment, params.group)
        except Exception:
            return False
        
        # Validate commitment point
        if C is None or not params.group.check_point(C):
            return False
        
        # Convert scalars to petlib Bn for elliptic curve operations
        z_v_bn = Bn.from_decimal(str(z_v))
        z_b_bn = Bn.from_decimal(str(z_b))
        c_bn = Bn.from_decimal(str(c))
        
        # Left side: z_v*G + z_b*H
        left_side = z_v_bn * params.G + z_b_bn * params.H
        
        # Right side: A + c*C
        right_side = A + c_bn * C
        
        # Verify equation holds
        # Note: EcPt equality in petlib uses point comparison
        if left_side != right_side:
            return False
        
        # ====================================================================
        # Proof Valid
        # ====================================================================
        
        return True
        
    except Exception:
        # Any cryptographic error means proof is invalid
        # Return False instead of raising (no information leakage)
        return False


# ============================================================================
# CHALLENGE COMPUTATION (Fiat-Shamir Transform)
# ============================================================================


def _compute_challenge(
    G: EcPt,
    H: EcPt,
    commitment: bytes,
    announcement: bytes,
    context: bytes
) -> bytes:
    """
    Compute Fiat-Shamir challenge via SHA-256 with length-prefixed encoding.
    
    ⚠️ SECURITY CRITICAL: Must use length-prefixed concatenation
    
    Challenge = SHA-256(
        len(G) || G || len(H) || H || 
        len(C) || C || len(A) || A || 
        len(ctx) || ctx
    )
    
    This binds the challenge to:
    - Generators (G, H) - prevents cross-curve attacks
    - Commitment being proven - prevents proof substitution
    - Announcement from prover - prevents replay attacks
    - Additional context - prevents cross-protocol attacks
    
    Length-Prefixing Prevents Collision Attacks:
        Without length prefixes:
            Hash(b"AB" || b"CD") == Hash(b"ABC" || b"D")  # COLLISION!
        
        With length prefixes:
            Hash(2 || b"AB" || 2 || b"CD") != Hash(3 || b"ABC" || 1 || b"D")  # SAFE
    
    Args:
        G: Generator point G
        H: Generator point H
        commitment: Commitment bytes (33 bytes)
        announcement: Announcement point bytes (33 bytes)
        context: Additional context bytes
    
    Returns:
        32-byte challenge (caller converts to scalar mod GROUP_ORDER)
    
    Example:
        >>> params = setup_curve()
        >>> commitment = b'\\x02' + b'\\x00' * 32
        >>> announcement = b'\\x03' + b'\\x00' * 32
        >>> challenge = _compute_challenge(
        ...     params.G, params.H, commitment, announcement, b"test"
        ... )
        >>> assert len(challenge) == 32
    
    Security Notes:
        - Length-prefixing prevents collision attacks
        - Deterministic (same inputs → same challenge)
        - Binds challenge to all protocol parameters
    """
    # Initialize SHA-256 hash
    h = hashlib.sha256()
    
    # Export generators to bytes (compressed point format)
    G_bytes = G.export()
    H_bytes = H.export()
    
    # ========================================================================
    # Length-Prefixed Concatenation (CRITICAL for security)
    # ========================================================================
    
    # Hash generator G with length prefix
    h.update(len(G_bytes).to_bytes(4, 'big'))
    h.update(G_bytes)
    
    # Hash generator H with length prefix
    h.update(len(H_bytes).to_bytes(4, 'big'))
    h.update(H_bytes)
    
    # Hash commitment with length prefix
    h.update(len(commitment).to_bytes(4, 'big'))
    h.update(commitment)
    
    # Hash announcement with length prefix
    h.update(len(announcement).to_bytes(4, 'big'))
    h.update(announcement)
    
    # Hash context with length prefix
    h.update(len(context).to_bytes(4, 'big'))
    h.update(context)
    
    # Return 32-byte challenge
    # Caller will convert to scalar: int.from_bytes(challenge, 'big') % GROUP_ORDER
    return h.digest()

