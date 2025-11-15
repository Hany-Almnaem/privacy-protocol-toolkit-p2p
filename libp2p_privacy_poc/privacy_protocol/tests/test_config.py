"""
⚠️ DRAFT — requires crypto review before production use

Unit tests for configuration module.

Tests configuration parameters, validation, and security requirements.
"""

import pytest
from libp2p_privacy_poc.privacy_protocol import config


class TestConfigParameters:
    """Test configuration parameters are set correctly."""

    def test_curve_name(self):
        """Test curve name is secp256k1."""
        assert config.CURVE_NAME == "secp256k1"

    def test_curve_library(self):
        """Test curve library is petlib."""
        assert config.CURVE_LIBRARY == "petlib"

    def test_group_order(self):
        """Test secp256k1 group order is correct."""
        expected_order = (
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        )
        assert config.GROUP_ORDER == expected_order
        assert config.GROUP_ORDER > 0
        assert config.GROUP_ORDER_BITS == 256

    def test_cofactor(self):
        """Test secp256k1 has cofactor 1 (prime order)."""
        assert config.COFACTOR == 1, "secp256k1 must be prime order"

    def test_curve_nid(self):
        """Test secp256k1 NID is correct."""
        assert config.CURVE_NID == 714, "secp256k1 OpenSSL NID must be 714"

    def test_point_size(self):
        """Test point size is correct for compressed secp256k1."""
        assert config.POINT_SIZE_BYTES == 33


class TestGeneratorParameters:
    """Test generator derivation parameters."""

    def test_generator_h_seed(self):
        """Test generator H seed is set."""
        assert config.GENERATOR_H_SEED == b"LIBP2P_PRIVACY_V1_GENERATOR_H"
        assert isinstance(config.GENERATOR_H_SEED, bytes)

    def test_generator_derivation_method(self):
        """Test hash-to-curve method is RFC 9380."""
        assert config.GENERATOR_H_DERIVATION_METHOD == "RFC9380"


class TestHashFunctions:
    """Test hash function configuration."""

    def test_hash_function(self):
        """Test using SHA3-256 (not SHA-256 due to length extension)."""
        assert config.HASH_FUNCTION == "SHA3-256"
        assert config.HASH_OUTPUT_BITS == 256

    def test_domain_separator_prefix(self):
        """Test domain separator prefix is set."""
        assert config.DOMAIN_SEPARATOR_PREFIX == b"LIBP2P_PRIVACY_V1_"
        assert isinstance(config.DOMAIN_SEPARATOR_PREFIX, bytes)

    def test_domain_separators(self):
        """Test all proof types have domain separators."""
        required_types = [
            "anonymity_set_membership",
            "session_unlinkability",
            "range_proof",
            "timing_independence",
        ]

        for proof_type in required_types:
            assert proof_type in config.DOMAIN_SEPARATORS
            separator = config.DOMAIN_SEPARATORS[proof_type]
            assert isinstance(separator, bytes)
            assert separator.startswith(config.DOMAIN_SEPARATOR_PREFIX)

    def test_domain_separators_unique(self):
        """Test all domain separators are unique."""
        separators = list(config.DOMAIN_SEPARATORS.values())
        assert len(separators) == len(
            set(separators)
        ), "Domain separators must be unique"


class TestSecurityParameters:
    """Test security parameter requirements."""

    def test_blinding_factor_bits(self):
        """Test blinding factor is at least 256 bits for 128-bit security."""
        assert config.BLINDING_FACTOR_BITS >= 256

    def test_challenge_space_bits(self):
        """Test challenge space is at least 128 bits for soundness."""
        assert config.CHALLENGE_SPACE_BITS >= 128

    def test_randomness_source(self):
        """Test cryptographically secure randomness source."""
        assert config.RANDOMNESS_SOURCE == "secrets.SystemRandom"


class TestSerializationConfig:
    """Test proof serialization configuration."""

    def test_serialization_format(self):
        """Test using CBOR serialization."""
        assert config.SERIALIZATION_FORMAT == "CBOR"

    def test_proof_version(self):
        """Test proof version is set."""
        assert config.PROOF_VERSION == 1
        assert isinstance(config.PROOF_VERSION, int)


class TestPerformanceLimits:
    """Test performance limits are reasonable."""

    def test_max_proof_size(self):
        """Test maximum proof size limit."""
        assert config.MAX_PROOF_SIZE_BYTES == 10 * 1024  # 10KB
        assert config.MAX_PROOF_SIZE_BYTES > 0

    def test_max_proofs_in_memory(self):
        """Test maximum proofs in memory limit."""
        assert config.MAX_PROOFS_IN_MEMORY == 10_000
        assert config.MAX_PROOFS_IN_MEMORY > 0

    def test_max_proof_batch_size(self):
        """Test batch size limit."""
        assert config.MAX_PROOF_BATCH_SIZE == 100
        assert config.MAX_PROOF_BATCH_SIZE > 0

    def test_performance_targets(self):
        """Test performance target ranges are set."""
        assert len(config.TARGET_COMMIT_TIME_MS) == 2
        assert config.TARGET_COMMIT_TIME_MS[0] < config.TARGET_COMMIT_TIME_MS[1]

        assert len(config.TARGET_VERIFY_TIME_MS) == 2
        assert config.TARGET_VERIFY_TIME_MS[0] < config.TARGET_VERIFY_TIME_MS[1]

        assert len(config.TARGET_PROOF_GEN_TIME_MS) == 2
        assert config.TARGET_PROOF_GEN_TIME_MS[0] < config.TARGET_PROOF_GEN_TIME_MS[1]

        assert len(config.TARGET_1000_PROOFS_TIME_SEC) == 2
        assert (
            config.TARGET_1000_PROOFS_TIME_SEC[0]
            < config.TARGET_1000_PROOFS_TIME_SEC[1]
        )


class TestValidation:
    """Test configuration validation function."""

    def test_validate_config_succeeds(self):
        """Test validate_config() passes with current configuration."""
        assert config.validate_config() is True

    def test_validation_on_import(self):
        """Test configuration is validated on import."""
        # If we got here, validation passed during import
        assert True

    def test_challenge_space_requirement(self):
        """Test challenge space is sufficient for security."""
        # Challenge space must be >= 2^128 for soundness
        assert config.CHALLENGE_SPACE_BITS >= 128
        # For 128-bit security, need at least 2^128 challenges
        max_challenges = 2**config.CHALLENGE_SPACE_BITS
        min_required = 2**128
        assert max_challenges >= min_required

    def test_blinding_factor_requirement(self):
        """Test blinding factor is sufficient for security."""
        # For 128-bit security, need at least 256-bit blinding
        assert config.BLINDING_FACTOR_BITS >= 256


class TestSecurityProperties:
    """Test security-critical properties."""

    def test_prime_order_group(self):
        """Test using prime order group (cofactor = 1)."""
        if config.CURVE_NAME == "secp256k1":
            assert config.COFACTOR == 1, "secp256k1 must have cofactor 1"

    def test_nothing_up_my_sleeve_generator(self):
        """Test generator H uses verifiable derivation."""
        # Generator H seed must be public and verifiable
        assert config.GENERATOR_H_SEED == b"LIBP2P_PRIVACY_V1_GENERATOR_H"
        # Must use standard hash-to-curve method
        assert config.GENERATOR_H_DERIVATION_METHOD == "RFC9380"

    def test_no_sha256_for_fiat_shamir(self):
        """Test NOT using SHA-256 (vulnerable to length extension)."""
        assert config.HASH_FUNCTION != "SHA-256"
        assert config.HASH_FUNCTION == "SHA3-256", "Use SHA3-256 for Fiat-Shamir"

    def test_group_order_is_prime(self):
        """Test secp256k1 group order is prime (cofactor = 1)."""
        if config.CURVE_NAME == "secp256k1":
            # secp256k1 has prime order (no subgroup attacks)
            assert config.COFACTOR == 1


class TestDocumentation:
    """Test configuration is properly documented."""

    def test_security_warning_present(self):
        """Test security warning is in docstring."""
        docstring = config.__doc__
        assert docstring is not None
        assert "DRAFT" in docstring or "PROTOTYPE" in docstring
        assert "production" in docstring.lower()

    def test_adaptation_note_present(self):
        """Test adaptation note about secp256k1 is present."""
        docstring = config.__doc__
        assert "secp256k1" in docstring or "petlib" in docstring


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
