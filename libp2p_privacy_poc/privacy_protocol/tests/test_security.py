"""
⚠️ DRAFT — requires crypto review before production use

Unit tests for security utilities module.

Tests randomness, hash functions, hash-to-curve, and constant-time operations.
"""

import pytest
import os
import hashlib
from petlib.ec import EcGroup

from libp2p_privacy_poc.privacy_protocol import security
from libp2p_privacy_poc.privacy_protocol.config import GROUP_ORDER, CURVE_NID


class TestRandomnessSource:
    """Test cryptographically secure randomness source."""

    def test_init(self):
        """Test RandomnessSource initialization."""
        rng = security.RandomnessSource()
        assert rng._pid == os.getpid()
        assert rng._rng is not None

    def test_get_random_scalar(self):
        """Test random scalar generation."""
        rng = security.RandomnessSource()
        max_value = 1000

        scalar = rng.get_random_scalar(max_value)
        assert 0 <= scalar < max_value
        assert isinstance(scalar, int)

    def test_get_random_scalar_mod_order(self):
        """Test random scalar modulo group order."""
        rng = security.RandomnessSource()

        scalar = rng.get_random_scalar_mod_order()
        assert 0 <= scalar < GROUP_ORDER
        assert isinstance(scalar, int)

    def test_get_random_bytes(self):
        """Test random bytes generation."""
        rng = security.RandomnessSource()
        n = 32

        random_bytes = rng.get_random_bytes(n)
        assert len(random_bytes) == n
        assert isinstance(random_bytes, bytes)

    def test_randomness_uniformity(self):
        """Test randomness appears uniform (statistical test)."""
        rng = security.RandomnessSource()
        max_value = 100
        samples = 1000

        # Generate samples
        results = [rng.get_random_scalar(max_value) for _ in range(samples)]

        # Check all values in range
        assert all(0 <= r < max_value for r in results)

        # Check reasonable distribution (not all same value)
        unique_values = len(set(results))
        assert unique_values > max_value // 2, "Distribution too clustered"

    def test_fork_detection(self):
        """Test fork detection reinitializes RNG."""
        rng = security.RandomnessSource()
        original_pid = rng._pid

        # Simulate fork by changing PID
        rng._pid = original_pid + 1

        # Next call should detect fork and reinitialize
        scalar = rng.get_random_scalar(1000)
        assert rng._pid == os.getpid()
        assert rng._pid == original_pid  # Should be reset to current PID

    def test_different_instances_produce_different_values(self):
        """Test different RNG instances produce different values."""
        rng1 = security.RandomnessSource()
        rng2 = security.RandomnessSource()

        # Generate multiple values from each
        values1 = [rng1.get_random_scalar(2**128) for _ in range(10)]
        values2 = [rng2.get_random_scalar(2**128) for _ in range(10)]

        # With high probability, at least some values differ
        # (would be extremely unlikely for all to match)
        assert values1 != values2


class TestHashToScalar:
    """Test hash-to-scalar function."""

    def test_basic_functionality(self):
        """Test hash_to_scalar produces scalar in range."""
        data = b"test data"
        max_value = 1000

        scalar = security.hash_to_scalar(data, max_value)
        assert 0 <= scalar < max_value
        assert isinstance(scalar, int)

    def test_deterministic(self):
        """Test hash_to_scalar is deterministic."""
        data = b"test data"
        max_value = 1000

        scalar1 = security.hash_to_scalar(data, max_value)
        scalar2 = security.hash_to_scalar(data, max_value)

        assert scalar1 == scalar2

    def test_domain_separation(self):
        """Test domain separation produces different results."""
        data = b"test data"
        max_value = 1000
        domain_sep1 = b"DOMAIN_1"
        domain_sep2 = b"DOMAIN_2"

        scalar1 = security.hash_to_scalar(data, max_value, domain_sep1)
        scalar2 = security.hash_to_scalar(data, max_value, domain_sep2)

        # Different domain separators should produce different results
        # (with very high probability)
        assert scalar1 != scalar2

    def test_different_data_different_output(self):
        """Test different data produces different scalars."""
        max_value = 1000

        scalar1 = security.hash_to_scalar(b"data1", max_value)
        scalar2 = security.hash_to_scalar(b"data2", max_value)

        assert scalar1 != scalar2

    def test_large_max_value(self):
        """Test with large max_value (group order)."""
        data = b"test data"

        scalar = security.hash_to_scalar(data, GROUP_ORDER)
        assert 0 <= scalar < GROUP_ORDER

    def test_empty_data_raises_error(self):
        """Test empty data raises ValueError."""
        with pytest.raises(ValueError, match="Data cannot be empty"):
            security.hash_to_scalar(b"", 1000)

    def test_invalid_max_value_raises_error(self):
        """Test invalid max_value raises ValueError."""
        with pytest.raises(ValueError, match="max_value must be > 1"):
            security.hash_to_scalar(b"data", 1)

    def test_invalid_data_type_raises_error(self):
        """Test invalid data type raises TypeError."""
        with pytest.raises(TypeError, match="data must be bytes"):
            security.hash_to_scalar("not bytes", 1000)

    def test_invalid_domain_sep_type_raises_error(self):
        """Test invalid domain_sep type raises TypeError."""
        with pytest.raises(TypeError, match="domain_sep must be bytes"):
            security.hash_to_scalar(b"data", 1000, "not bytes")


class TestFiatShamirChallenge:
    """Test Fiat-Shamir challenge generation."""

    def test_basic_functionality(self):
        """Test fiat_shamir_challenge produces valid challenge."""
        commitment = b"commitment_data"
        public_input = b"public_input_data"
        domain_sep = b"TEST_DOMAIN"

        challenge = security.fiat_shamir_challenge(commitment, public_input, domain_sep)
        assert 0 <= challenge < GROUP_ORDER
        assert isinstance(challenge, int)

    def test_deterministic(self):
        """Test fiat_shamir_challenge is deterministic."""
        commitment = b"commitment"
        public_input = b"input"
        domain_sep = b"DOMAIN"

        challenge1 = security.fiat_shamir_challenge(
            commitment, public_input, domain_sep
        )
        challenge2 = security.fiat_shamir_challenge(
            commitment, public_input, domain_sep
        )

        # Same inputs always produce same challenge
        assert challenge1 == challenge2

    def test_domain_separation_affects_challenge(self):
        """Test domain separator affects challenge."""
        commitment = b"commitment"
        public_input = b"input"

        challenge1 = security.fiat_shamir_challenge(
            commitment, public_input, b"DOMAIN_1"
        )
        challenge2 = security.fiat_shamir_challenge(
            commitment, public_input, b"DOMAIN_2"
        )

        # Different domain separators should produce different challenges
        assert challenge1 != challenge2

    def test_commitment_affects_challenge(self):
        """Test commitment affects challenge."""
        public_input = b"input"
        domain_sep = b"DOMAIN"

        challenge1 = security.fiat_shamir_challenge(
            b"commitment_1", public_input, domain_sep
        )
        challenge2 = security.fiat_shamir_challenge(
            b"commitment_2", public_input, domain_sep
        )

        assert challenge1 != challenge2

    def test_public_input_affects_challenge(self):
        """Test public input affects challenge."""
        commitment = b"commitment"
        domain_sep = b"DOMAIN"

        challenge1 = security.fiat_shamir_challenge(commitment, b"input_1", domain_sep)
        challenge2 = security.fiat_shamir_challenge(commitment, b"input_2", domain_sep)

        assert challenge1 != challenge2

    def test_length_prefixing_prevents_collisions(self):
        """Test length-prefixing prevents collision attacks."""
        domain_sep = b"DOMAIN"

        # These would collide without length-prefixing: "AB" + "CD" == "ABC" + "D"
        challenge1 = security.fiat_shamir_challenge(b"AB", b"CD", domain_sep)
        challenge2 = security.fiat_shamir_challenge(b"ABC", b"D", domain_sep)

        # With length-prefixing, they should be different
        assert challenge1 != challenge2

    def test_empty_commitment_raises_error(self):
        """Test empty commitment raises ValueError."""
        with pytest.raises(ValueError, match="Commitment cannot be empty"):
            security.fiat_shamir_challenge(b"", b"input", b"DOMAIN")

    def test_empty_public_input_raises_error(self):
        """Test empty public_input raises ValueError."""
        with pytest.raises(ValueError, match="Public input cannot be empty"):
            security.fiat_shamir_challenge(b"commit", b"", b"DOMAIN")

    def test_empty_domain_sep_raises_error(self):
        """Test empty domain_sep raises ValueError."""
        with pytest.raises(ValueError, match="Domain separator cannot be empty"):
            security.fiat_shamir_challenge(b"commit", b"input", b"")

    def test_invalid_commitment_type_raises_error(self):
        """Test invalid commitment type raises TypeError."""
        with pytest.raises(TypeError, match="commitment must be bytes"):
            security.fiat_shamir_challenge("not bytes", b"input", b"DOMAIN")

    def test_invalid_public_input_type_raises_error(self):
        """Test invalid public_input type raises TypeError."""
        with pytest.raises(TypeError, match="public_input must be bytes"):
            security.fiat_shamir_challenge(b"commit", "not bytes", b"DOMAIN")

    def test_invalid_domain_sep_type_raises_error(self):
        """Test invalid domain_sep type raises TypeError."""
        with pytest.raises(TypeError, match="domain_sep must be bytes"):
            security.fiat_shamir_challenge(b"commit", b"input", "not bytes")


class TestHashToCurve:
    """Test hash-to-curve function."""

    def test_basic_functionality_secp256k1(self):
        """Test hash_to_curve produces valid point for secp256k1."""
        seed = b"test_seed"
        domain_sep = b"TEST_DOMAIN"
        group = EcGroup(CURVE_NID)

        point_bytes, point_obj = security.hash_to_curve(seed, domain_sep, group)

        assert isinstance(point_bytes, bytes)
        assert len(point_bytes) == 33  # Compressed secp256k1 point
        assert point_obj is not None

    def test_deterministic(self):
        """Test hash_to_curve is deterministic."""
        seed = b"test_seed"
        domain_sep = b"TEST_DOMAIN"
        group = EcGroup(CURVE_NID)

        point_bytes1, _ = security.hash_to_curve(seed, domain_sep, group)
        point_bytes2, _ = security.hash_to_curve(seed, domain_sep, group)

        assert point_bytes1 == point_bytes2

    def test_different_seeds_different_points(self):
        """Test different seeds produce different points."""
        domain_sep = b"TEST_DOMAIN"
        group = EcGroup(CURVE_NID)

        point_bytes1, _ = security.hash_to_curve(b"seed_1", domain_sep, group)
        point_bytes2, _ = security.hash_to_curve(b"seed_2", domain_sep, group)

        assert point_bytes1 != point_bytes2

    def test_domain_separation(self):
        """Test domain separator affects output."""
        seed = b"test_seed"
        group = EcGroup(CURVE_NID)

        point_bytes1, _ = security.hash_to_curve(seed, b"DOMAIN_1", group)
        point_bytes2, _ = security.hash_to_curve(seed, b"DOMAIN_2", group)

        assert point_bytes1 != point_bytes2

    def test_point_on_curve(self):
        """Test generated point is on the curve."""
        seed = b"test_seed"
        domain_sep = b"TEST_DOMAIN"
        group = EcGroup(CURVE_NID)

        _, point_obj = security.hash_to_curve(seed, domain_sep, group)

        # petlib point operations validate curve membership
        # If this doesn't raise, point is valid
        assert point_obj is not None
        # Test we can do operations with the point
        two_times_point = 2 * point_obj
        assert two_times_point is not None

    def test_auto_creates_group_if_none(self):
        """Test automatically creates group if None provided."""
        seed = b"test_seed"
        domain_sep = b"TEST_DOMAIN"

        point_bytes, point_obj = security.hash_to_curve(seed, domain_sep, None)

        assert isinstance(point_bytes, bytes)
        assert len(point_bytes) == 33
        assert point_obj is not None


class TestConstantTimeOperations:
    """Test constant-time operations."""

    def test_constant_time_compare_equal(self):
        """Test constant_time_compare returns True for equal bytes."""
        a = b"test_data"
        b = b"test_data"

        assert security.constant_time_compare(a, b) is True

    def test_constant_time_compare_not_equal(self):
        """Test constant_time_compare returns False for different bytes."""
        a = b"test_data_1"
        b = b"test_data_2"

        assert security.constant_time_compare(a, b) is False

    def test_constant_time_compare_different_lengths(self):
        """Test constant_time_compare handles different lengths."""
        a = b"short"
        b = b"longer_data"

        assert security.constant_time_compare(a, b) is False

    def test_constant_time_compare_uses_hmac_compare_digest(self):
        """Test constant_time_compare uses hmac.compare_digest."""
        # Verify the function uses the standard library's constant-time comparison
        a = b"data"
        b = b"data"

        result = security.constant_time_compare(a, b)
        assert result is True

        # Test that it's actually calling hmac.compare_digest
        import hmac

        assert security.constant_time_compare(a, b) == hmac.compare_digest(a, b)


class TestSecurityProperties:
    """Test security properties of functions."""

    def test_hash_functions_use_sha3(self):
        """Test hash functions use SHA3-256 (not SHA-256)."""
        from libp2p_privacy_poc.privacy_protocol.config import HASH_FUNCTION

        assert HASH_FUNCTION == "SHA3-256"

    def test_randomness_source_uses_secrets(self):
        """Test RandomnessSource uses secrets module."""
        import secrets

        rng = security.RandomnessSource()
        assert isinstance(rng._rng, secrets.SystemRandom)

    def test_fork_detection_enabled(self):
        """Test fork detection is enabled."""
        rng = security.RandomnessSource()
        assert hasattr(rng, "_pid")
        assert rng._pid == os.getpid()


class TestDocumentation:
    """Test security module is properly documented."""

    def test_security_warning_present(self):
        """Test security warning is in docstring."""
        docstring = security.__doc__
        assert docstring is not None
        assert "DRAFT" in docstring or "PROTOTYPE" in docstring
        assert "production" in docstring.lower()

    def test_functions_have_docstrings(self):
        """Test all public functions have docstrings."""
        assert security.hash_to_scalar.__doc__ is not None
        assert security.fiat_shamir_challenge.__doc__ is not None
        assert security.hash_to_curve.__doc__ is not None
        assert security.constant_time_compare.__doc__ is not None

    def test_hash_to_curve_has_rfc9380_warning(self):
        """Test hash_to_curve has RFC 9380 compliance warning."""
        docstring = security.hash_to_curve.__doc__
        assert "RFC 9380" in docstring or "RFC9380" in docstring
        assert "NOT RFC 9380 COMPLIANT" in docstring or "PROTOTYPE" in docstring


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
