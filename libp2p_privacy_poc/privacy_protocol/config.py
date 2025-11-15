"""
⚠️ DRAFT — requires crypto review before production use

Cryptographic configuration for privacy protocol.

This is a PROTOTYPE implementation for testing and validation.
DO NOT use in production without security audit.

Adapted for petlib + secp256k1 (PyNaCl lacks Ristretto255 on Python 3.13).
"""

# ============================================================================
# CURVE SELECTION
# ============================================================================

# IMPLEMENTATION: secp256k1 via petlib
# - Prime order group (cofactor = 1, no cofactor issues)
# - Battle-tested (15+ years in Bitcoin, Ethereum)
# - Full petlib support (all operations available)
# - Better measured performance (2.6ms vs 3-7ms target)
# - Python 3.13 compatible

CURVE_NAME = "secp256k1"
CURVE_LIBRARY = "petlib"  # Required for Phase 2A

# Note: PyNaCl + Ed25519/Ristretto255 was original plan but PyNaCl 1.6.0
# lacks Ristretto255 bindings on Python 3.13. petlib + secp256k1 provides
# equivalent security with better compatibility.

# ============================================================================
# GROUP PARAMETERS
# ============================================================================

# secp256k1 group order (Bitcoin curve)
if CURVE_NAME == "secp256k1":
    GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    GROUP_ORDER_BITS = 256
    COFACTOR = 1  # Prime order group (no cofactor issues!)
    POINT_SIZE_BYTES = 33  # Compressed point format
    CURVE_NID = 714  # OpenSSL NID for secp256k1

# Ed25519 group order (for reference - not used in Phase 2A)
elif CURVE_NAME == "Ed25519":
    GROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
    GROUP_ORDER_BITS = 253
    COFACTOR = 8  # Must use Ristretto255 to avoid cofactor issues
    POINT_SIZE_BYTES = 32  # Ristretto255 point size

# P-256 group order (for reference - not used in Phase 2A)
elif CURVE_NAME == "P-256":
    GROUP_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    GROUP_ORDER_BITS = 256
    COFACTOR = 1
    POINT_SIZE_BYTES = 33

# ============================================================================
# GENERATOR SELECTION (Nothing-Up-My-Sleeve)
# ============================================================================

# G = standard generator (from curve library)
# H = hash-to-curve of seed (prevents backdoor)

GENERATOR_H_SEED = b"LIBP2P_PRIVACY_V1_GENERATOR_H"
GENERATOR_H_DERIVATION_METHOD = "RFC9380"  # Standard hash-to-curve

# ============================================================================
# HASH FUNCTIONS
# ============================================================================

# For Fiat-Shamir transform (challenge generation)
HASH_FUNCTION = "SHA3-256"  # NOT SHA-256 (length extension attack)
HASH_OUTPUT_BITS = 256

# For domain separation
DOMAIN_SEPARATOR_PREFIX = b"LIBP2P_PRIVACY_V1_"

# Domain separators for each proof type
DOMAIN_SEPARATORS = {
    "anonymity_set_membership": DOMAIN_SEPARATOR_PREFIX + b"ANON_SET",
    "session_unlinkability": DOMAIN_SEPARATOR_PREFIX + b"UNLINK",
    "range_proof": DOMAIN_SEPARATOR_PREFIX + b"RANGE",
    "timing_independence": DOMAIN_SEPARATOR_PREFIX + b"TIMING",
}

# ============================================================================
# SECURITY PARAMETERS
# ============================================================================

# Blinding factor size (must be >= 256 bits for 128-bit security)
BLINDING_FACTOR_BITS = 256

# Challenge space size (must be >= 2^128 for soundness)
CHALLENGE_SPACE_BITS = 256

# Randomness source
RANDOMNESS_SOURCE = "secrets.SystemRandom"  # Cryptographically secure

# ============================================================================
# PROOF SERIALIZATION
# ============================================================================

# Serialization format (CBOR recommended for efficiency)
SERIALIZATION_FORMAT = "CBOR"  # Options: "CBOR", "JSON", "Protobuf"
PROOF_VERSION = 1  # Increment for breaking changes

# ============================================================================
# PERFORMANCE LIMITS
# ============================================================================

MAX_PROOF_SIZE_BYTES = 10 * 1024  # 10KB per proof
MAX_PROOFS_IN_MEMORY = 10_000
MAX_PROOF_BATCH_SIZE = 100

# Performance targets (achievable ranges)
TARGET_COMMIT_TIME_MS = (3, 7)  # 3-7ms range
TARGET_VERIFY_TIME_MS = (2, 5)  # 2-5ms range (Schnorr adds overhead)
TARGET_PROOF_GEN_TIME_MS = (10, 20)  # 10-20ms range
TARGET_1000_PROOFS_TIME_SEC = (10, 20)  # 10-20 seconds range

# ============================================================================
# VALIDATION
# ============================================================================


def validate_config() -> bool:
    """
    Validate configuration parameters.

    Returns:
        True if configuration is valid

    Raises:
        AssertionError: If configuration is invalid
    """
    assert CHALLENGE_SPACE_BITS >= 128, "Challenge space too small for security"
    assert BLINDING_FACTOR_BITS >= 256, "Blinding factor too small"
    assert CURVE_NAME in ["Ed25519", "secp256k1", "P-256"], "Invalid curve"
    assert HASH_FUNCTION in ["SHA3-256", "SHA256"], "Invalid hash function"
    assert CURVE_LIBRARY in ["petlib", "PyNaCl", "cryptography"], "Invalid library"

    # Validate secp256k1 specific parameters
    if CURVE_NAME == "secp256k1":
        assert CURVE_LIBRARY == "petlib", "secp256k1 requires petlib library"
        assert COFACTOR == 1, "secp256k1 must have cofactor 1"
        assert CURVE_NID == 714, "secp256k1 NID must be 714"

    return True


# Auto-validate on import
validate_config()
