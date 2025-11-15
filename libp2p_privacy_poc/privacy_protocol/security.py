"""
⚠️ DRAFT — requires crypto review before production use

Security utilities for cryptographic operations.

This is a PROTOTYPE implementation for testing and validation.
DO NOT use in production without security audit.

Adapted for petlib + secp256k1 (PyNaCl lacks Ristretto255 on Python 3.13).
"""

import os
import secrets
import hashlib
import hmac
from typing import Optional, Tuple

from .config import CURVE_NAME, GROUP_ORDER, HASH_FUNCTION, DOMAIN_SEPARATOR_PREFIX


# ============================================================================
# GROUP ORDER VALIDATION (Run at module import)
# ============================================================================


def _validate_group_order():
    """
    Validate GROUP_ORDER is reasonable.

    Prevents configuration errors by checking GROUP_ORDER matches
    expected value for secp256k1.

    Raises:
        ValueError: If GROUP_ORDER is invalid
    """
    if GROUP_ORDER <= 0:
        raise ValueError(f"Invalid GROUP_ORDER: {GROUP_ORDER}")

    if GROUP_ORDER < 2**128:
        raise ValueError(f"GROUP_ORDER too small (< 2^128): {GROUP_ORDER}")

    # Check if GROUP_ORDER matches expected value for secp256k1
    secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if CURVE_NAME == "secp256k1" and GROUP_ORDER != secp256k1_order:
        raise ValueError(
            f"GROUP_ORDER mismatch for secp256k1: "
            f"expected {hex(secp256k1_order)}, got {hex(GROUP_ORDER)}"
        )


# Validate GROUP_ORDER on module import (fail fast)
_validate_group_order()


# ============================================================================
# RANDOMNESS SOURCE (Fork-Safe)
# ============================================================================


class RandomnessSource:
    """
    Cryptographically secure randomness with fork detection.

    Prevents catastrophic randomness reuse if process forks.

    Example:
        >>> rng = RandomnessSource()
        >>> scalar = rng.get_random_scalar_mod_order()
        >>> # After fork, RNG automatically reinitializes
    """

    def __init__(self):
        """Initialize randomness source with fork detection."""
        self._pid = os.getpid()
        self._rng = secrets.SystemRandom()

    def get_random_scalar(self, max_value: int) -> int:
        """
        Get random scalar in [0, max_value).

        Args:
            max_value: Upper bound (exclusive)

        Returns:
            Random scalar in [0, max_value)

        Note:
            Uses randrange(0, max_value) which returns [0, max_value).
            SystemRandom doesn't have randbelow() method.
        """
        if os.getpid() != self._pid:
            self.__init__()
        return self._rng.randrange(0, max_value)

    def get_random_bytes(self, n: int) -> bytes:
        """
        Get n cryptographically secure random bytes.

        Args:
            n: Number of bytes to generate

        Returns:
            n random bytes
        """
        if os.getpid() != self._pid:
            self.__init__()
        return secrets.token_bytes(n)

    def get_random_scalar_mod_order(self) -> int:
        """
        Get random scalar modulo group order.

        Returns:
            Random scalar in [0, GROUP_ORDER)
        """
        return self.get_random_scalar(GROUP_ORDER)


# ============================================================================
# HASH FUNCTIONS
# ============================================================================


def hash_to_scalar(
    data: bytes, max_value: int, domain_sep: Optional[bytes] = None
) -> int:
    """
    Hash data to scalar in [0, max_value) with domain separation.

    Args:
        data: Data to hash (must be non-empty)
        max_value: Maximum value (exclusive, must be > 1)
        domain_sep: Optional domain separator

    Returns:
        Scalar in [0, max_value)

    Raises:
        ValueError: If inputs are invalid
        TypeError: If inputs are wrong type

    Security Note:
        Uses modulo reduction which introduces slight bias for
        non-power-of-2 max_value. For cryptographic security,
        max_value should be prime and close to 2^256.
    """
    # Input validation
    if not isinstance(data, bytes):
        raise TypeError(f"data must be bytes, got {type(data)}")

    if not data:
        raise ValueError("Data cannot be empty")

    if max_value <= 1:
        raise ValueError(f"max_value must be > 1, got {max_value}")

    # Domain separation
    if domain_sep:
        if not isinstance(domain_sep, bytes):
            raise TypeError(f"domain_sep must be bytes, got {type(domain_sep)}")
        data = domain_sep + data

    # Hash
    if HASH_FUNCTION == "SHA3-256":
        h = hashlib.sha3_256(data)
    else:
        h = hashlib.sha256(data)

    # Modulo reduction (slight bias acceptable for prototype)
    result = int.from_bytes(h.digest(), "big") % max_value

    return result


def fiat_shamir_challenge(
    commitment: bytes,
    public_input: bytes,
    domain_sep: bytes,
) -> int:
    """
    Generate deterministic Fiat-Shamir challenge with domain separation.

    Prevents cross-protocol attacks by using domain separator.
    Uses length-prefixed encoding to prevent collision attacks.

    Args:
        commitment: Commitment bytes (must be non-empty)
        public_input: Public input bytes (must be non-empty)
        domain_sep: Domain separator (must be non-empty)

    Returns:
        Challenge scalar in [0, GROUP_ORDER)

    Raises:
        ValueError: If inputs are invalid

    Security Notes:
        - Uses length-prefixed encoding (len || data) to prevent collisions
        - Challenge is deterministic (enables reproducible proofs)
        - Challenge must be unpredictable before commitment is made

    Example:
        >>> challenge = fiat_shamir_challenge(b"commit", b"public", b"DOMAIN")
        >>> # Same inputs always produce same challenge
    """
    # Input validation
    if not isinstance(commitment, bytes):
        raise TypeError(f"commitment must be bytes, got {type(commitment)}")
    if not isinstance(public_input, bytes):
        raise TypeError(f"public_input must be bytes, got {type(public_input)}")
    if not isinstance(domain_sep, bytes):
        raise TypeError(f"domain_sep must be bytes, got {type(domain_sep)}")

    if not commitment:
        raise ValueError("Commitment cannot be empty")
    if not public_input:
        raise ValueError("Public input cannot be empty")
    if not domain_sep:
        raise ValueError("Domain separator cannot be empty")

    # Hash function selection
    h = hashlib.sha3_256() if HASH_FUNCTION == "SHA3-256" else hashlib.sha256()

    # Domain separation (length-prefixed)
    h.update(len(domain_sep).to_bytes(4, "big"))
    h.update(domain_sep)

    # Commitment (length-prefixed)
    h.update(len(commitment).to_bytes(4, "big"))
    h.update(commitment)

    # Public input (length-prefixed)
    h.update(len(public_input).to_bytes(4, "big"))
    h.update(public_input)

    # Return challenge
    return int.from_bytes(h.digest(), "big") % GROUP_ORDER


# ============================================================================
# HASH-TO-CURVE (via petlib) - ADAPTED FOR SECP256K1
# ============================================================================


def hash_to_curve(
    seed: bytes, domain_separator: bytes, group=None
) -> Tuple[bytes, object]:
    """
    Hash arbitrary data to elliptic curve point using petlib's hash_to_point.

    ⚠️ SECURITY WARNING: NOT RFC 9380 COMPLIANT

    petlib's hash_to_point uses hash-and-increment method, NOT RFC 9380.
    This is deterministic but may have timing side-channels (variable iterations).

    For production, implement proper RFC 9380:
    - expand_message_xmd() for domain separation
    - map_to_curve() with Simplified SWU
    - clear_cofactor() if needed

    PROTOTYPE ONLY - DO NOT USE IN PRODUCTION WITHOUT CRYPTO REVIEW

    Args:
        seed: Seed data to hash
        domain_separator: Domain separator for context
        group: petlib EcGroup instance (optional, auto-created if None)

    Returns:
        Tuple of (point_bytes, point_object) where point_object is EcPt

    Raises:
        NotImplementedError: If curve not supported
        ValueError: If inputs are invalid

    Security Note:
        Generator H derivation uses this function. The Nothing-Up-My-Sleeve
        property is maintained by using a public seed, but RFC 9380 compliance
        should be added in Phase 2B for production readiness.
    """
    if CURVE_NAME == "secp256k1":
        if group is None:
            from petlib.ec import EcGroup

            group = EcGroup(714)  # secp256k1 NID

        # Proper domain separation (DST || msg format)
        # Note: This is basic concatenation, not RFC 9380 expand_message_xmd
        combined = domain_separator + b"||" + seed

        # Use petlib's hash_to_point
        # WARNING: This uses hash-and-increment, NOT RFC 9380
        # May have timing side-channels (variable loop iterations)
        point = group.hash_to_point(combined)

        # Export point to bytes (compressed format)
        point_bytes = point.export()

        return point_bytes, point

    elif CURVE_NAME == "Ed25519":
        # Ed25519 implementation (not used in Phase 2A, kept for reference)
        raise NotImplementedError(
            "Ed25519 hash-to-curve requires PyNaCl Ristretto255 "
            "(not available on Python 3.13)"
        )

    else:
        raise ValueError(f"Unsupported curve: {CURVE_NAME}")


# ============================================================================
# CONSTANT-TIME OPERATIONS
# ============================================================================


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.

    Uses hmac.compare_digest which is designed to prevent timing attacks
    by taking constant time regardless of the input values.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if a == b, False otherwise

    Security Note:
        This is the standard library's constant-time comparison.
        Safe for cryptographic use.
    """
    return hmac.compare_digest(a, b)
