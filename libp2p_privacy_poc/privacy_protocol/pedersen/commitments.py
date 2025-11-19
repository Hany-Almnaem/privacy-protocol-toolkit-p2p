"""
⚠️ DRAFT — requires crypto review before production use

Pedersen commitment implementation using petlib + secp256k1.

This is a PROTOTYPE implementation for testing and validation.
DO NOT use in production without security audit.

Pedersen Commitments:
    A commitment scheme with the following properties:
    - Hiding: Commitment reveals nothing about the value
    - Binding: Cannot change value after commitment
    - Homomorphic: Commitments can be added

Mathematical Definition:
    C = value * G + blinding * H
    where G, H are elliptic curve generators (no known discrete log relation)

Security Requirements:
    1. Generators G and H must have unknown discrete log relation
    2. Blinding factor must be cryptographically random
    3. Value and blinding must be in [0, GROUP_ORDER)
    4. Verification should be constant-time

Implementation Details:
    - Curve: secp256k1 (NID 714)
    - G: Standard secp256k1 generator
    - H: hash_to_point(GENERATOR_H_SEED) - Nothing-Up-My-Sleeve
    - Library: petlib 0.0.45+
"""

from typing import Tuple, Optional, Any
from dataclasses import dataclass
import threading

try:
    from petlib.ec import EcGroup, EcPt
    from petlib.bn import Bn
except ImportError:
    raise ImportError(
        "petlib is required for Pedersen commitments. "
        "Install with: pip install petlib"
    )

from ..security import RandomnessSource, constant_time_compare
from ..exceptions import CryptographicError, SecurityError
from ..config import (
    CURVE_NAME,
    CURVE_LIBRARY,
    GROUP_ORDER,
    GENERATOR_H_SEED,
    CURVE_NID,
    POINT_SIZE_BYTES,
    COFACTOR,
)


# ============================================================================
# CURVE SETUP
# ============================================================================


@dataclass
class CurveParameters:
    """
    Elliptic curve parameters for Pedersen commitments.

    Attributes:
        curve: Curve name (e.g., "secp256k1")
        library: Cryptographic library (e.g., "petlib")
        group: Elliptic curve group (EcGroup)
        G: First generator (standard generator)
        H: Second generator (Nothing-Up-My-Sleeve via hash-to-point)
        order: Group order (number of points)

    Security Properties:
        - G and H must have unknown discrete log relation
        - H is derived deterministically via hash-to-point
        - Group order must be prime (cofactor = 1 for secp256k1)
    """

    curve: str
    library: str
    group: Any  # EcGroup
    G: Any  # EcPt
    H: Any  # EcPt
    order: int

    def __post_init__(self):
        """Validate curve parameters after initialization."""
        # Ensure order is int for comparison
        if not isinstance(self.order, int):
            self.order = int(self.order)

        if self.order != GROUP_ORDER:
            raise ValueError(
                f"Group order mismatch: expected {GROUP_ORDER}, "
                f"got {self.order}"
            )

        # Validate actual cofactor from curve
        # For secp256k1: cofactor = 1 (prime order group)
        # Compute: cofactor = #E(Fp) / order
        # For secp256k1, #E(Fp) = order (cofactor = 1)
        try:
            # petlib doesn't expose cofactor directly, but we can verify
            # by checking that generator has order equal to group order
            generator_order = int(self.group.order())
            if generator_order != self.order:
                raise SecurityError(
                    f"Generator order {generator_order} != group order "
                    f"{self.order}. Curve may have cofactor > 1."
                )
        except Exception:
            # If we can't verify cofactor, at least check config
            pass

        # Verify configuration matches expectation
        if COFACTOR != 1:
            raise SecurityError(
                f"Configuration error: COFACTOR={COFACTOR}, expected 1. "
                "Pedersen commitments require prime order curves only."
            )


def setup_curve(
    curve_name: Optional[str] = None, library: Optional[str] = None
) -> CurveParameters:
    """
        Setup elliptic curve and generators for Pedersen commitments.


    ⚠️ SECURITY CRITICAL - TRUST ASSUMPTIONS

    This function initializes the cryptographic group and derives
    the two generators G and H needed for Pedersen commitments.

    **Generator H Discrete Log Assumption:**

    We derive H via hash-to-point(GENERATOR_H_SEED) using petlib's
    try-and-increment method. Security of Pedersen commitments relies on:

    1. **Hash function (SHA-256) acts as random oracle**
       - No one can predict output without computing hash
       - Standard assumption in cryptographic protocols

    2. **No one knows discrete log α such that H = α*G**
       - If someone knew α, they could break binding property
       - Computationally infeasible given random H derivation

    3. **Quantum resistance assumption (current)**
       - Quantum computers cannot efficiently compute discrete logs
       - This is a standard assumption (may change with quantum advances)

    **Provable Security:**
    - Not formally proven, but standard assumption in ECC
    - Same assumption used in Bitcoin, Ethereum, TLS, etc.

    **Verification:**
    - Anyone can recompute H = hash_to_point(GENERATOR_H_SEED)
    - Derivation is deterministic and publicly verifiable
    - Seed is Nothing-Up-My-Sleeve constant

    **Production Alternative:**
    - For production, consider using standardized NUMS point (e.g., SEC2)
    - Community consensus provides additional trust
    - Phase 2A uses deterministic derivation for prototype

    Security Requirements:
        1. G and H must have no known discrete log relation
        2. H must be derived via Nothing-Up-My-Sleeve method
        3. Group order must be prime (cofactor = 1)
        4. Curve parameters must match configuration

    Args:
        curve_name: Name of elliptic curve (defaults to config.CURVE_NAME)
        library: Cryptographic library (defaults to config.CURVE_LIBRARY)

    Returns:
        CurveParameters: Initialized curve parameters with G, H

    Raises:
        ValueError: If curve/library combination is unsupported
        SecurityError: If curve doesn't meet security requirements
        CryptographicError: If curve initialization fails

    Example:
        >>> params = setup_curve()
        >>> print(params.curve, params.order)
        secp256k1 11579208923731619542...  # noqa: E501

    Note:
        - G is the standard secp256k1 generator
        - H is derived via hash_to_point(GENERATOR_H_SEED)
        - This ensures no known discrete log relation between G and H
    """
    curve_name = curve_name or CURVE_NAME
    library = library or CURVE_LIBRARY

    # Validate curve/library combination
    if curve_name != "secp256k1":
        raise ValueError(
            f"Only secp256k1 is supported, got {curve_name}. "
            "Other curves require additional implementation."
        )

    if library != "petlib":
        raise ValueError(
            f"Only petlib is supported, got {library}. "
            "Other libraries require additional implementation."
        )

    try:
        # Create secp256k1 group using petlib
        # CURVE_NID = 714 (OpenSSL NID for secp256k1)
        group = EcGroup(CURVE_NID)

        # G = standard secp256k1 generator (built-in)
        # This is the same generator used in Bitcoin/Ethereum
        G = group.generator()

        # H = hash-to-point of Nothing-Up-My-Sleeve seed
        # ⚠️ TRUST ASSUMPTION: This assumes no one knows discrete log α
        # where H = α*G. Security relies on hash function randomness.
        # petlib's hash_to_point implements try-and-increment method.
        # Anyone can verify: H = hash_to_point("LIBP2P_PRIVACY_V1_GENERATOR_H")
        H = group.hash_to_point(GENERATOR_H_SEED)

        # Verify group order matches configuration
        # Note: group.order() returns petlib Bn, convert to int
        order = int(group.order())
        if order != GROUP_ORDER:
            raise SecurityError(
                f"Group order mismatch: expected {GROUP_ORDER}, got {order}"
            )

        # Create and return parameters
        params = CurveParameters(
            curve=curve_name,
            library=library,
            group=group,
            G=G,
            H=H,
            order=order,
        )

        return params

    except Exception as e:
        if isinstance(e, (ValueError, SecurityError)):
            raise
        raise CryptographicError(
            f"Failed to initialize curve {curve_name}: {e}"
        ) from e


# ============================================================================
# COMMITMENT OPERATIONS
# ============================================================================


def commit(
    value: int,
    blinding: Optional[int] = None,
    params: Optional[CurveParameters] = None,
    randomness_source: Optional[RandomnessSource] = None,
) -> Tuple[bytes, int]:
    """
    Create a Pedersen commitment to a value.

    ⚠️ SECURITY CRITICAL

    Computes: C = value * G + blinding * H

    The blinding factor provides hiding - without it, commitments
    are deterministic and reveal the value. The blinding factor
    MUST be:
    - Cryptographically random
    - Unique for each commitment
    - Kept secret until opening
    - Generated with fork-safe randomness

    Args:
        value: Integer value to commit to (must be in [0, GROUP_ORDER))
        blinding: Blinding factor (generated if None)
        params: Curve parameters (initialized if None)
        randomness_source: Source for random blinding (created if None)

    Returns:
        Tuple of (commitment_bytes, blinding_factor):
                - commitment_bytes: Serialized elliptic curve point
                  (33 bytes)
            - blinding_factor: The blinding used (for later opening)

    Raises:
        ValueError: If value or blinding is out of range
        CryptographicError: If commitment computation fails

    Example:
        >>> params = setup_curve()
        >>> commitment, blinding = commit(42, params=params)
        >>> assert len(commitment) == 33  # Compressed point
        >>> assert 0 <= blinding < params.order

    Security Notes:
        - Value and blinding are reduced modulo group order
        - Blinding MUST be kept secret until opening
        - Same value with different blinding gives different
          commitment
        - Commitment is binding - cannot change value after commit
    """
    # Initialize parameters if not provided
    if params is None:
        params = setup_curve()

    # Initialize randomness source if not provided
    if randomness_source is None:
        randomness_source = RandomnessSource()

    # Validate value is in valid range
    if not isinstance(value, int):
        raise ValueError(f"Value must be an integer, got {type(value)}")

    if value < 0:
        raise ValueError(f"Value must be non-negative, got {value}")

    if value >= GROUP_ORDER:
        raise ValueError(
            f"Value must be less than group order "
            f"({GROUP_ORDER}), got {value}"
        )

    # Generate blinding factor if not provided
    if blinding is None:
        # Generate random scalar using petlib's group order
        # This ensures the value is within Bn's bounds
        order_bn = params.group.order()
        blinding_bn = order_bn.random()
        blinding = int(blinding_bn)
    else:
        # Validate provided blinding
        if not isinstance(blinding, int):
            raise ValueError(
                f"Blinding must be an integer, got {type(blinding)}"
            )

        if blinding < 0:
            raise ValueError(f"Blinding must be non-negative, got {blinding}")

        if blinding >= GROUP_ORDER:
            raise ValueError(
                f"Blinding must be less than group order "
                f"({GROUP_ORDER}), got {blinding}"
            )

    try:
        # Get group order as Bn for modular operations
        order_bn = params.group.order()

        # Convert Python int to petlib Bn using byte representation
        # This is the most reliable method for all values in [0, GROUP_ORDER)
        # secp256k1 scalars are 32 bytes (256 bits)
        value_bytes = value.to_bytes(32, byteorder='big')
        value_bn = Bn.from_binary(value_bytes)

        blinding_bytes = blinding.to_bytes(32, byteorder='big')
        blinding_bn = Bn.from_binary(blinding_bytes)

        # Compute Pedersen commitment: C = value*G + blinding*H
        # petlib uses efficient elliptic curve scalar multiplication
        commitment_point = value_bn * params.G + blinding_bn * params.H

        # Export commitment to bytes (compressed format)
        # Compressed format is 33 bytes: 1 byte prefix + 32 bytes x-coord
        commitment_bytes = commitment_point.export()

        # Validate output size
        if len(commitment_bytes) != POINT_SIZE_BYTES:
            raise CryptographicError(
                f"Commitment size mismatch: expected {POINT_SIZE_BYTES} "
                f"bytes, got {len(commitment_bytes)}"
            )

        # Return commitment and blinding as Python int
        return commitment_bytes, int(blinding_bn)

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise CryptographicError(f"Failed to compute commitment: {e}") from e


def verify_commitment(
    commitment_bytes: bytes,
    value: int,
    blinding: int,
    params: Optional[CurveParameters] = None,
) -> bool:
    """
    Verify a Pedersen commitment.

    ⚠️ SECURITY CRITICAL

    Verifies that: commitment == value * G + blinding * H

    This function recomputes the expected commitment and compares
    it to the provided commitment. Comparison should be constant-time
    to prevent timing attacks.

    ⚠️ LENIENT SEMANTICS: Values and blinding factors are automatically
    reduced modulo GROUP_ORDER. This means:
    - verify_commitment(c, GROUP_ORDER + 10, b) is equivalent to
      verify_commitment(c, 10, b)
    - This is needed for homomorphic operations where sums exceed GROUP_ORDER

    Args:
        commitment_bytes: Serialized commitment to verify (33 bytes)
        value: Claimed committed value (reduced mod GROUP_ORDER internally)
        blinding: Claimed blinding factor (reduced mod GROUP_ORDER internally)
        params: Curve parameters (initialized if None)

    Returns:
        bool: True if commitment is valid, False otherwise

    Raises:
        ValueError: If inputs are invalid
        CryptographicError: If verification computation fails

    Example:
        >>> params = setup_curve()
        >>> commitment, blinding = commit(42, params=params)
        >>> assert verify_commitment(commitment, 42, blinding, params)
        >>> assert not verify_commitment(commitment, 43, blinding, params)
        >>> 
        >>> # Lenient behavior: automatic modular reduction
        >>> c1, b1 = commit(GROUP_ORDER - 5, params=params)
        >>> # Both succeed (equivalent after reduction):
        >>> assert verify_commitment(c1, GROUP_ORDER - 5, b1, params)
        >>> assert verify_commitment(c1, 2*GROUP_ORDER - 5, b1, params)

    Security Notes:
        - Uses constant-time comparison to prevent timing attacks
        - Returns False on any error (don't leak information)
        - Validates all inputs before computation
        - Does NOT reveal why verification failed
        - ⚠️ PROTOTYPE LIMITATION: Does not reject identity point
          (commitment to value=0, blinding=0 reveals the value)
    """
    # Initialize parameters if not provided
    if params is None:
        params = setup_curve()

    # Validate commitment bytes
    if not isinstance(commitment_bytes, bytes):
        raise ValueError(
            f"Commitment must be bytes, got {type(commitment_bytes)}"
        )

    if len(commitment_bytes) != POINT_SIZE_BYTES:
        raise ValueError(
            f"Commitment must be {POINT_SIZE_BYTES} bytes, "
            f"got {len(commitment_bytes)}"
        )

    # Validate value
    if not isinstance(value, int):
        raise ValueError(f"Value must be an integer, got {type(value)}")

    if value < 0:
        raise ValueError(f"Value must be non-negative, got {value}")

    # Allow value >= GROUP_ORDER - will be reduced modulo order
    # This is needed for homomorphic operations where v1 + v2 may exceed order

    # Validate blinding
    if not isinstance(blinding, int):
        raise ValueError(f"Blinding must be an integer, got {type(blinding)}")

    if blinding < 0:
        raise ValueError(f"Blinding must be non-negative, got {blinding}")

    # Allow blinding >= GROUP_ORDER - will be reduced modulo order
    # This is needed for homomorphic operations where b1 + b2 may exceed order

    try:
        # Get group order as Bn for modular operations
        order_bn = params.group.order()

        # Convert Python int to petlib Bn using byte representation
        # Reduce modulo order to handle overflow from homomorphic operations
        value_mod = value % int(order_bn)
        blinding_mod = blinding % int(order_bn)

        value_bytes = value_mod.to_bytes(32, byteorder='big')
        value_bn = Bn.from_binary(value_bytes)

        blinding_bytes = blinding_mod.to_bytes(32, byteorder='big')
        blinding_bn = Bn.from_binary(blinding_bytes)

        # Recompute expected commitment
        # C_expected = value * G + blinding * H
        expected_point = value_bn * params.G + blinding_bn * params.H

        # Import commitment from bytes
        # This may raise if commitment_bytes is invalid
        try:
            commitment_point = EcPt.from_binary(commitment_bytes, params.group)
        except Exception:
            # Invalid point encoding - commitment is invalid
            return False

        # Validate point is not None and is on curve
        if commitment_point is None:
            return False

        if not params.group.check_point(commitment_point):
            return False

        # ⚠️ PROTOTYPE LIMITATION: Identity point check
        # A commitment to (value=0, blinding=0) would be the identity point,
        # which reveals the committed value. For production, consider rejecting.
        # For now, we document this limitation but allow it.
        # Uncomment below to reject identity point:
        # if commitment_point.is_infinite():
        #     return False

        # ⚠️ CRITICAL: Use constant-time comparison to prevent timing attacks
        # Export both points to normalized byte representation
        # Then use constant-time byte comparison via hmac.compare_digest
        commitment_bytes_normalized = commitment_point.export()
        expected_bytes = expected_point.export()

        # Constant-time comparison (prevents timing side-channel attacks)
        result = constant_time_compare(
            commitment_bytes_normalized, expected_bytes
        )

        return bool(result)

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        # On any cryptographic error, return False
        # This prevents leaking information about why verification failed
        return False


def open_commitment(
    commitment_bytes: bytes,
    value: int,
    blinding: int,
    params: Optional[CurveParameters] = None,
) -> bool:
    """
    Open (reveal) a Pedersen commitment.

    ⚠️ SECURITY WARNING

    Opening a commitment reveals both the value and blinding factor.
    This is typically only done:
    1. In testing/debugging
    2. When proving knowledge of opening
    3. When the commitment is no longer needed to be hidden

    This function is essentially an alias for verify_commitment()
    but with more explicit semantics about revealing the opening.

    Args:
        commitment_bytes: Commitment to open
        value: Revealed value
        blinding: Revealed blinding factor
        params: Curve parameters (initialized if None)

    Returns:
        bool: True if opening is valid

    Raises:
        ValueError: If inputs are invalid
        CryptographicError: If verification fails

    Example:
        >>> params = setup_curve()
        >>> commitment, blinding = commit(42, params=params)
        >>> assert open_commitment(commitment, 42, blinding, params)

    Note:
        - This reveals the committed value
        - Use only when necessary
        - In production, prefer zero-knowledge proofs of opening
    """
    return verify_commitment(commitment_bytes, value, blinding, params)


# ============================================================================
# HOMOMORPHIC OPERATIONS
# ============================================================================


def add_commitments(
    commitment1_bytes: bytes,
    commitment2_bytes: bytes,
    params: Optional[CurveParameters] = None,
) -> bytes:
    """
    Add two Pedersen commitments homomorphically.

    Pedersen commitments are additively homomorphic:
        commit(v1, r1) + commit(v2, r2) = commit(v1 + v2, r1 + r2)

    ⚠️ IMPORTANT: Values and blindings are added MODULO group order.

    This allows operating on commitments without revealing values.

    Args:
        commitment1_bytes: First commitment (33 bytes)
        commitment2_bytes: Second commitment (33 bytes)
        params: Curve parameters (initialized if None)

    Returns:
        bytes: Sum commitment (33 bytes)

    Raises:
        ValueError: If commitments are invalid
        CryptographicError: If addition fails

    Example:
        >>> params = setup_curve()
        >>> c1, b1 = commit(10, params=params)
        >>> c2, b2 = commit(20, params=params)
        >>> c_sum = add_commitments(c1, c2, params)
        >>> # ⚠️ Use modular addition for blindings!
        >>> total_value = (10 + 20) % GROUP_ORDER  # = 30
        >>> total_blinding = (b1 + b2) % GROUP_ORDER
        >>> assert verify_commitment(c_sum, total_value, total_blinding, params)
        >>> # Or use helper function:
        >>> total_blinding_alt = add_commitment_blindings(b1, b2)
        >>> assert verify_commitment(c_sum, 30, total_blinding_alt, params)

    Security Notes:
        - Addition is performed on curve points
        - Blinding factors add modulo GROUP_ORDER
        - Does not reveal individual values
        - Useful for confidential transactions
        - Always use modular arithmetic for values and blindings
    """
    # Initialize parameters if not provided
    if params is None:
        params = setup_curve()

    # Validate commitment sizes
    if len(commitment1_bytes) != POINT_SIZE_BYTES:
        raise ValueError(
            f"Commitment1 must be {POINT_SIZE_BYTES} bytes, "
            f"got {len(commitment1_bytes)}"
        )

    if len(commitment2_bytes) != POINT_SIZE_BYTES:
        raise ValueError(
            f"Commitment2 must be {POINT_SIZE_BYTES} bytes, "
            f"got {len(commitment2_bytes)}"
        )

    try:
        # Import commitments from bytes
        c1_point = EcPt.from_binary(commitment1_bytes, params.group)
        c2_point = EcPt.from_binary(commitment2_bytes, params.group)

        # Add curve points: C1 + C2
        c_sum_point = c1_point + c2_point

        # Export result to bytes
        c_sum_bytes = c_sum_point.export()

        return c_sum_bytes

    except Exception as e:
        raise CryptographicError(f"Failed to add commitments: {e}") from e


# ============================================================================
# HOMOMORPHIC ARITHMETIC HELPERS
# ============================================================================


def add_commitment_values(value1: int, value2: int) -> int:
    """
    Add committed values with modular reduction.

    When adding commitments homomorphically, values must be added
    modulo group order.

    Args:
        value1: First value
        value2: Second value

    Returns:
        (value1 + value2) % GROUP_ORDER

    Example:
        >>> v1 = GROUP_ORDER - 10
        >>> v2 = 20
        >>> v_sum = add_commitment_values(v1, v2)
        >>> assert v_sum == 10  # (GROUP_ORDER - 10 + 20) % GROUP_ORDER
    """
    return (value1 + value2) % GROUP_ORDER


def add_commitment_blindings(blinding1: int, blinding2: int) -> int:
    """
    Add blinding factors with modular reduction.

    When adding commitments homomorphically, blinding factors must be
    added modulo group order.

    Args:
        blinding1: First blinding factor
        blinding2: Second blinding factor

    Returns:
        (blinding1 + blinding2) % GROUP_ORDER

    Example:
        >>> params = setup_curve()
        >>> c1, b1 = commit(10, params=params)
        >>> c2, b2 = commit(20, params=params)
        >>> c_sum = add_commitments(c1, c2, params)
        >>> total_blinding = add_commitment_blindings(b1, b2)
        >>> assert verify_commitment(c_sum, 30, total_blinding, params)
    """
    return (blinding1 + blinding2) % GROUP_ORDER


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def commitment_to_point(
    commitment_bytes: bytes, params: Optional[CurveParameters] = None
) -> Any:
    """
    Convert commitment bytes to elliptic curve point.

    Utility function for operations that need the point representation.

    Args:
        commitment_bytes: Serialized commitment (33 bytes)
        params: Curve parameters (initialized if None)

    Returns:
        EcPt: Elliptic curve point

    Raises:
        ValueError: If commitment is invalid
        CryptographicError: If deserialization fails

    Example:
        >>> params = setup_curve()
        >>> commitment, _ = commit(42, params=params)
        >>> point = commitment_to_point(commitment, params)
        >>> assert point.group.check_point(point)
    """
    if params is None:
        params = setup_curve()

    if len(commitment_bytes) != POINT_SIZE_BYTES:
        raise ValueError(
            f"Commitment must be {POINT_SIZE_BYTES} bytes, "
            f"got {len(commitment_bytes)}"
        )

    try:
        point = EcPt.from_binary(commitment_bytes, params.group)
        return point
    except Exception as e:
        raise CryptographicError(
            f"Failed to deserialize commitment: {e}"
        ) from e


def validate_commitment_format(commitment_bytes: bytes) -> bool:
    """
    Validate that commitment bytes have correct format.

    Checks size and basic structure without full curve operations.
    This is a fast check for obviously invalid commitments.

    Args:
        commitment_bytes: Bytes to validate

    Returns:
        bool: True if format is valid (doesn't guarantee point validity)

    Example:
        >>> params = setup_curve()
        >>> commitment, _ = commit(42, params=params)
        >>> assert validate_commitment_format(commitment)
        >>> assert not validate_commitment_format(b"invalid")
    """
    if not isinstance(commitment_bytes, bytes):
        return False

    if len(commitment_bytes) != POINT_SIZE_BYTES:
        return False

    # Check compressed point prefix (0x02 or 0x03 for secp256k1)
    if commitment_bytes[0] not in (0x02, 0x03):
        return False

    return True


# ============================================================================
# MODULE-LEVEL CACHE (Optional optimization)
# ============================================================================

# Cache curve parameters to avoid repeated initialization
_CURVE_PARAMS_CACHE: Optional[CurveParameters] = None
_CACHE_LOCK = threading.Lock()


def get_cached_curve_params() -> CurveParameters:
    """
    Get cached curve parameters (initialize if needed).

    Optimization to avoid repeated curve initialization.
    Thread-safe using double-checked locking pattern.

    Returns:
        CurveParameters: Cached parameters

    Example:
        >>> params = get_cached_curve_params()
        >>> commitment, _ = commit(42, params=params)

    Thread Safety:
        Multiple threads can safely call this function concurrently.
        Only one thread will initialize the cache.
    """
    global _CURVE_PARAMS_CACHE

    # Fast path: cache already initialized (no lock needed)
    if _CURVE_PARAMS_CACHE is not None:
        return _CURVE_PARAMS_CACHE

    # Slow path: acquire lock and initialize
    with _CACHE_LOCK:
        # Double-check: another thread may have initialized while we waited
        if _CURVE_PARAMS_CACHE is None:
            _CURVE_PARAMS_CACHE = setup_curve()

    return _CURVE_PARAMS_CACHE


def clear_curve_params_cache():
    """
    Clear cached curve parameters.

    Useful for testing or when parameters need to be reinitialized.
    Thread-safe.

    Example:
        >>> clear_curve_params_cache()
        >>> # Next call to get_cached_curve_params() will reinitialize
    """
    global _CURVE_PARAMS_CACHE

    with _CACHE_LOCK:
        _CURVE_PARAMS_CACHE = None
