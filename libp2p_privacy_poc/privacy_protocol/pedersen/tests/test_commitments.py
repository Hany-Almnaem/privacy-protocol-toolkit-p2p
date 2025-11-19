"""
⚠️ DRAFT — requires crypto review before production use

Tests for Pedersen commitment implementation.

This is a PROTOTYPE implementation for testing and validation.
DO NOT use in production without security audit.

Test Coverage:
1. Curve setup and parameter validation
2. Commitment creation and validation
3. Commitment verification
4. Opening commitments
5. Homomorphic addition
6. Edge cases and error handling
7. Performance benchmarks
8. Security properties (hiding, binding)
"""

import pytest
from petlib.ec import EcGroup, EcPt

from ..commitments import (
    setup_curve,
    commit,
    verify_commitment,
    open_commitment,
    add_commitments,
    add_commitment_values,
    add_commitment_blindings,
    commitment_to_point,
    validate_commitment_format,
    get_cached_curve_params,
    clear_curve_params_cache,
    CurveParameters,
)
from ...security import RandomnessSource
from ...exceptions import CryptographicError, SecurityError
from ...config import GROUP_ORDER, POINT_SIZE_BYTES, CURVE_NID


# ============================================================================
# TEST: CURVE SETUP
# ============================================================================


class TestCurveSetup:
    """Test elliptic curve initialization."""

    def test_setup_curve_default(self):
        """Setup curve with default parameters."""
        params = setup_curve()

        assert params is not None
        assert params.curve == "secp256k1"
        assert params.library == "petlib"
        assert params.order == GROUP_ORDER
        assert params.G is not None
        assert params.H is not None

    def test_setup_curve_explicit(self):
        """Setup curve with explicit parameters."""
        params = setup_curve(curve_name="secp256k1", library="petlib")

        assert params.curve == "secp256k1"
        assert params.library == "petlib"

    def test_generators_are_distinct(self):
        """Generators G and H must be different."""
        params = setup_curve()

        # G and H should be different points
        assert params.G != params.H

    def test_generators_are_on_curve(self):
        """Generators must be valid curve points."""
        params = setup_curve()

        # Check that G and H are on the curve
        assert params.group.check_point(params.G)
        assert params.group.check_point(params.H)

    def test_generator_g_is_standard(self):
        """G should be the standard secp256k1 generator."""
        params = setup_curve()
        group = EcGroup(CURVE_NID)

        # G should equal the standard generator
        assert params.G == group.generator()

    def test_generator_h_is_deterministic(self):
        """H should be deterministically derived."""
        params1 = setup_curve()
        params2 = setup_curve()

        # H should be the same across multiple calls
        assert params1.H == params2.H

    def test_group_order_correct(self):
        """Group order must match configuration."""
        params = setup_curve()

        # secp256k1 order
        expected_order = (
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        )
        assert params.order == expected_order

    def test_unsupported_curve_raises(self):
        """Unsupported curves should raise ValueError."""
        with pytest.raises(ValueError, match="Only secp256k1 is supported"):
            setup_curve(curve_name="P-256")

    def test_unsupported_library_raises(self):
        """Unsupported libraries should raise ValueError."""
        with pytest.raises(ValueError, match="Only petlib is supported"):
            setup_curve(library="cryptography")


# ============================================================================
# TEST: COMMITMENT CREATION
# ============================================================================


class TestCommitmentCreation:
    """Test Pedersen commitment creation."""

    def test_commit_basic(self):
        """Create basic commitment."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)

        assert isinstance(commitment, bytes)
        assert len(commitment) == POINT_SIZE_BYTES
        assert isinstance(blinding, int)
        assert 0 <= blinding < GROUP_ORDER

    def test_commit_with_explicit_blinding(self):
        """Create commitment with explicit blinding factor."""
        params = setup_curve()
        value = 42
        blinding = 12345

        commitment, returned_blinding = commit(
            value, blinding=blinding, params=params
        )

        assert returned_blinding == blinding
        assert isinstance(commitment, bytes)

    def test_commit_generates_random_blinding(self):
        """Blinding should be random if not provided."""
        params = setup_curve()
        value = 42

        commitment1, blinding1 = commit(value, params=params)
        commitment2, blinding2 = commit(value, params=params)

        # Different blinding factors (with extremely high probability)
        assert blinding1 != blinding2
        # Different commitments (with extremely high probability)
        assert commitment1 != commitment2

    def test_commit_zero_value(self):
        """Commit to zero value."""
        params = setup_curve()

        commitment, blinding = commit(0, params=params)

        assert isinstance(commitment, bytes)
        assert verify_commitment(commitment, 0, blinding, params)

    def test_commit_max_value(self):
        """Commit to maximum value."""
        params = setup_curve()
        value = GROUP_ORDER - 1

        commitment, blinding = commit(value, params=params)

        assert isinstance(commitment, bytes)
        assert verify_commitment(commitment, value, blinding, params)

    def test_commit_negative_value_raises(self):
        """Negative values should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="must be non-negative"):
            commit(-1, params=params)

    def test_commit_value_exceeds_order_raises(self):
        """Values >= GROUP_ORDER should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="less than group order"):
            commit(GROUP_ORDER, params=params)

        with pytest.raises(ValueError, match="less than group order"):
            commit(GROUP_ORDER + 1, params=params)

    def test_commit_negative_blinding_raises(self):
        """Negative blinding should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="must be non-negative"):
            commit(42, blinding=-1, params=params)

    def test_commit_blinding_exceeds_order_raises(self):
        """Blinding >= GROUP_ORDER should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="less than group order"):
            commit(42, blinding=GROUP_ORDER, params=params)

    def test_commit_non_integer_value_raises(self):
        """Non-integer values should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="must be an integer"):
            commit("42", params=params)

        with pytest.raises(ValueError, match="must be an integer"):
            commit(42.5, params=params)

    def test_commit_non_integer_blinding_raises(self):
        """Non-integer blinding should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="must be an integer"):
            commit(42, blinding="100", params=params)

    def test_commit_initializes_params_if_none(self):
        """Commit should initialize params if not provided."""
        commitment, blinding = commit(42)

        assert isinstance(commitment, bytes)
        assert isinstance(blinding, int)

    def test_commit_uses_custom_randomness_source(self):
        """Commit should accept custom randomness source."""
        params = setup_curve()
        rng = RandomnessSource()

        commitment, blinding = commit(42, params=params, randomness_source=rng)

        assert isinstance(commitment, bytes)
        assert isinstance(blinding, int)


# ============================================================================
# TEST: COMMITMENT VERIFICATION
# ============================================================================


class TestCommitmentVerification:
    """Test Pedersen commitment verification."""

    def test_verify_valid_commitment(self):
        """Valid commitments should verify."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)
        result = verify_commitment(commitment, value, blinding, params)

        assert result is True

    def test_verify_invalid_value(self):
        """Incorrect value should fail verification."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)
        result = verify_commitment(commitment, 43, blinding, params)

        assert result is False

    def test_verify_invalid_blinding(self):
        """Incorrect blinding should fail verification."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)
        result = verify_commitment(commitment, value, blinding + 1, params)

        assert result is False

    def test_verify_corrupted_commitment(self):
        """Corrupted commitment bytes should fail verification."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)

        # Corrupt commitment bytes
        corrupted = bytes([commitment[0] ^ 0xFF]) + commitment[1:]

        result = verify_commitment(corrupted, value, blinding, params)

        assert result is False

    def test_verify_initializes_params_if_none(self):
        """Verify should initialize params if not provided."""
        commitment, blinding = commit(42)
        result = verify_commitment(commitment, 42, blinding)

        assert result is True

    def test_verify_invalid_commitment_size_raises(self):
        """Invalid commitment size should raise ValueError."""
        params = setup_curve()

        with pytest.raises(
            ValueError, match=f"must be {POINT_SIZE_BYTES} bytes"
        ):
            verify_commitment(b"invalid", 42, 100, params)

    def test_verify_invalid_commitment_type_raises(self):
        """Non-bytes commitment should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="must be bytes"):
            verify_commitment("invalid", 42, 100, params)

    def test_verify_negative_value_raises(self):
        """Negative value should raise ValueError."""
        params = setup_curve()
        commitment, blinding = commit(42, params=params)

        with pytest.raises(ValueError, match="must be non-negative"):
            verify_commitment(commitment, -1, blinding, params)

    def test_verify_value_exceeds_order_works(self):
        """Value >= GROUP_ORDER is reduced modulo order."""
        params = setup_curve()
        # Commit to value 10
        commitment, blinding = commit(10, params=params)

        # Verify with GROUP_ORDER + 10 (equivalent to 10 mod GROUP_ORDER)
        # This should work due to modular reduction
        result = verify_commitment(commitment, GROUP_ORDER + 10, blinding, params)
        assert result is True

    def test_verify_negative_blinding_raises(self):
        """Negative blinding should raise ValueError."""
        params = setup_curve()
        commitment, blinding = commit(42, params=params)

        with pytest.raises(ValueError, match="must be non-negative"):
            verify_commitment(commitment, 42, -1, params)

    def test_verify_blinding_exceeds_order_works(self):
        """Blinding >= GROUP_ORDER is reduced modulo order."""
        params = setup_curve()
        # Commit with blinding 100
        commitment, _ = commit(42, blinding=100, params=params)

        # Verify with GROUP_ORDER + 100 (equivalent to 100 mod GROUP_ORDER)
        # This should work due to modular reduction
        result = verify_commitment(commitment, 42, GROUP_ORDER + 100, params)
        assert result is True


# ============================================================================
# TEST: OPENING COMMITMENTS
# ============================================================================


class TestOpeningCommitments:
    """Test opening (revealing) commitments."""

    def test_open_valid_commitment(self):
        """Opening valid commitment should succeed."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)
        result = open_commitment(commitment, value, blinding, params)

        assert result is True

    def test_open_invalid_commitment(self):
        """Opening with wrong value should fail."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)
        result = open_commitment(commitment, 43, blinding, params)

        assert result is False

    def test_open_is_verify(self):
        """open_commitment should behave like verify_commitment."""
        params = setup_curve()
        value = 42

        commitment, blinding = commit(value, params=params)

        open_result = open_commitment(commitment, value, blinding, params)
        verify_result = verify_commitment(commitment, value, blinding, params)

        assert open_result == verify_result


# ============================================================================
# TEST: HOMOMORPHIC ADDITION
# ============================================================================


class TestHomomorphicAddition:
    """Test homomorphic properties of Pedersen commitments."""

    def test_add_commitments_basic(self):
        """Add two commitments."""
        params = setup_curve()

        # Create two commitments
        c1, b1 = commit(10, params=params)
        c2, b2 = commit(20, params=params)

        # Add commitments
        c_sum = add_commitments(c1, c2, params)

        # Verify sum commitment with helper function
        total_blinding = add_commitment_blindings(b1, b2)
        assert verify_commitment(c_sum, 30, total_blinding, params)

    def test_add_commitments_with_zero(self):
        """Add commitment with zero commitment."""
        params = setup_curve()

        c1, b1 = commit(42, params=params)
        c2, b2 = commit(0, params=params)

        c_sum = add_commitments(c1, c2, params)

        # Sum should equal first commitment (with combined blinding)
        assert verify_commitment(c_sum, 42, b1 + b2, params)

    def test_add_commitments_multiple(self):
        """Add multiple commitments sequentially."""
        params = setup_curve()

        c1, b1 = commit(10, params=params)
        c2, b2 = commit(20, params=params)
        c3, b3 = commit(30, params=params)

        c_sum_12 = add_commitments(c1, c2, params)
        c_sum_123 = add_commitments(c_sum_12, c3, params)

        # Verify final sum
        assert verify_commitment(c_sum_123, 60, b1 + b2 + b3, params)

    def test_add_commitments_invalid_size_raises(self):
        """Adding commitment with invalid size should raise."""
        params = setup_curve()
        c1, _ = commit(10, params=params)

        with pytest.raises(ValueError, match="must be.*bytes"):
            add_commitments(c1, b"invalid", params)

    def test_add_commitments_initializes_params(self):
        """add_commitments should initialize params if not provided."""
        c1, b1 = commit(10)
        c2, b2 = commit(20)

        c_sum = add_commitments(c1, c2)

        assert verify_commitment(c_sum, 30, b1 + b2)


# ============================================================================
# TEST: UTILITY FUNCTIONS
# ============================================================================


class TestHomomorphicHelpers:
    """Test homomorphic arithmetic helper functions."""

    def test_add_commitment_values(self):
        """Test add_commitment_values helper."""
        # Normal addition
        result = add_commitment_values(10, 20)
        assert result == 30

        # Overflow wraps around
        v1 = GROUP_ORDER - 10
        v2 = 20
        result = add_commitment_values(v1, v2)
        assert result == 10  # (GROUP_ORDER - 10 + 20) % GROUP_ORDER

    def test_add_commitment_blindings(self):
        """Test add_commitment_blindings helper."""
        # Normal addition
        result = add_commitment_blindings(100, 200)
        assert result == 300

        # Overflow wraps around
        b1 = GROUP_ORDER - 50
        b2 = 100
        result = add_commitment_blindings(b1, b2)
        assert result == 50  # (GROUP_ORDER - 50 + 100) % GROUP_ORDER

    def test_helpers_with_actual_commitments(self):
        """Test helpers work with real commitments."""
        params = setup_curve()

        c1, b1 = commit(10, params=params)
        c2, b2 = commit(20, params=params)
        c_sum = add_commitments(c1, c2, params)

        # Use helpers
        total_value = add_commitment_values(10, 20)
        total_blinding = add_commitment_blindings(b1, b2)

        assert verify_commitment(c_sum, total_value, total_blinding, params)


class TestUtilityFunctions:
    """Test utility functions."""

    def test_commitment_to_point(self):
        """Convert commitment bytes to curve point."""
        params = setup_curve()
        commitment, _ = commit(42, params=params)

        point = commitment_to_point(commitment, params)

        assert point is not None
        assert params.group.check_point(point)

    def test_commitment_to_point_invalid_size_raises(self):
        """Invalid commitment size should raise ValueError."""
        params = setup_curve()

        with pytest.raises(ValueError, match="must be.*bytes"):
            commitment_to_point(b"invalid", params)

    def test_validate_commitment_format_valid(self):
        """Valid commitment format should pass."""
        params = setup_curve()
        commitment, _ = commit(42, params=params)

        result = validate_commitment_format(commitment)

        assert result is True

    def test_validate_commitment_format_invalid_size(self):
        """Invalid size should fail format validation."""
        result = validate_commitment_format(b"invalid")

        assert result is False

    def test_validate_commitment_format_invalid_prefix(self):
        """Invalid prefix should fail format validation."""
        # Create bytes with wrong prefix (0x04 = uncompressed)
        invalid = b"\x04" + b"\x00" * (POINT_SIZE_BYTES - 1)

        result = validate_commitment_format(invalid)

        assert result is False

    def test_validate_commitment_format_non_bytes(self):
        """Non-bytes input should fail format validation."""
        result = validate_commitment_format("invalid")

        assert result is False

    def test_get_cached_curve_params(self):
        """Get cached curve parameters."""
        clear_curve_params_cache()

        params1 = get_cached_curve_params()
        params2 = get_cached_curve_params()

        # Should return same cached instance
        assert params1 is params2

    def test_clear_curve_params_cache(self):
        """Clear cached curve parameters."""
        params1 = get_cached_curve_params()
        clear_curve_params_cache()
        params2 = get_cached_curve_params()

        # Should return different instances after clear
        assert params1 is not params2


# ============================================================================
# TEST: EDGE CASES
# ============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_commit_boundary_value_zero(self):
        """Commit to zero (lower boundary)."""
        params = setup_curve()

        commitment, blinding = commit(0, params=params)

        assert verify_commitment(commitment, 0, blinding, params)

    def test_commit_boundary_value_max(self):
        """Commit to maximum value (upper boundary)."""
        params = setup_curve()
        max_value = GROUP_ORDER - 1

        commitment, blinding = commit(max_value, params=params)

        assert verify_commitment(commitment, max_value, blinding, params)

    def test_commit_boundary_blinding_zero(self):
        """Commit with zero blinding."""
        params = setup_curve()

        commitment, blinding = commit(42, blinding=0, params=params)

        assert blinding == 0
        assert verify_commitment(commitment, 42, 0, params)

    def test_commit_boundary_blinding_max(self):
        """Commit with maximum blinding."""
        params = setup_curve()
        max_blinding = GROUP_ORDER - 1

        commitment, returned_blinding = commit(
            42, blinding=max_blinding, params=params
        )

        assert returned_blinding == max_blinding
        assert verify_commitment(commitment, 42, max_blinding, params)

    def test_same_value_different_blinding(self):
        """Same value with different blinding gives different commitment."""
        params = setup_curve()
        value = 42

        c1, b1 = commit(value, blinding=100, params=params)
        c2, b2 = commit(value, blinding=200, params=params)

        # Different commitments
        assert c1 != c2
        # Both verify correctly
        assert verify_commitment(c1, value, b1, params)
        assert verify_commitment(c2, value, b2, params)

    def test_different_value_same_blinding(self):
        """Different values with same blinding give different commitments."""
        params = setup_curve()
        blinding = 12345

        c1, _ = commit(10, blinding=blinding, params=params)
        c2, _ = commit(20, blinding=blinding, params=params)

        # Different commitments
        assert c1 != c2


# ============================================================================
# TEST: SECURITY PROPERTIES
# ============================================================================


class TestSecurityProperties:
    """Test security properties of Pedersen commitments."""

    def test_hiding_property(self):
        """Commitment should hide the value (statistical test)."""
        params = setup_curve()

        # Create commitments to different values
        c1, _ = commit(42, params=params)
        c2, _ = commit(43, params=params)

        # Commitments should be different (randomness provides hiding)
        assert c1 != c2

        # Without blinding, would be deterministic (insecure)
        # Test that commitments to same value are different
        c3, _ = commit(42, params=params)
        assert c1 != c3  # Different due to different blinding

    def test_binding_property(self):
        """Commitment should be binding (can't change value after commit)."""
        params = setup_curve()

        # Create commitment
        commitment, blinding = commit(42, params=params)

        # Verify with correct value succeeds
        assert verify_commitment(commitment, 42, blinding, params)

        # Verify with different value fails (binding)
        assert not verify_commitment(commitment, 43, blinding, params)
        assert not verify_commitment(commitment, 41, blinding, params)

    def test_different_generators_give_different_commitments(self):
        """Using different generators must give different commitments."""
        params = setup_curve()

        # Commitment with generators in correct order
        value = 42
        blinding = 100
        c_normal = value * params.G + blinding * params.H

        # Commitment with generators swapped (WRONG - would break binding)
        c_swapped = value * params.H + blinding * params.G

        # Must be different
        assert c_normal != c_swapped

    def test_zero_blinding_still_verifies(self):
        """Zero blinding should still work (though not recommended)."""
        params = setup_curve()

        # Commitment with zero blinding (deterministic - not hiding!)
        c1, _ = commit(42, blinding=0, params=params)
        c2, _ = commit(42, blinding=0, params=params)

        # Same value with zero blinding gives same commitment
        assert c1 == c2

        # Still verifies correctly
        assert verify_commitment(c1, 42, 0, params)


# ============================================================================
# TEST: PERFORMANCE BENCHMARKS
# ============================================================================


class TestPerformance:
    """Test performance of commitment operations."""

    def test_setup_curve_performance(self, benchmark):
        """Benchmark curve setup."""
        result = benchmark(setup_curve)

        assert result is not None

    def test_commit_performance(self, benchmark):
        """Benchmark commitment creation."""
        params = setup_curve()

        result = benchmark(commit, 42, params=params)

        commitment, blinding = result
        assert isinstance(commitment, bytes)

    def test_verify_performance(self, benchmark):
        """Benchmark commitment verification."""
        params = setup_curve()
        commitment, blinding = commit(42, params=params)

        result = benchmark(verify_commitment, commitment, 42, blinding, params)

        assert result is True

    def test_commit_1000_operations(self):
        """Commit 1000 times (stress test)."""
        params = setup_curve()

        commitments = []
        for i in range(1000):
            commitment, blinding = commit(i, params=params)
            commitments.append((commitment, blinding, i))

        # Verify a sample
        for commitment, blinding, value in commitments[:10]:
            assert verify_commitment(commitment, value, blinding, params)


# ============================================================================
# TEST: INTEGRATION
# ============================================================================


class TestIntegration:
    """Integration tests for full workflows."""

    def test_full_workflow(self):
        """Complete commit-verify-open workflow."""
        # Setup
        params = setup_curve()

        # Commit
        value = 12345
        commitment, blinding = commit(value, params=params)

        # Verify
        assert verify_commitment(commitment, value, blinding, params)

        # Open (reveal)
        assert open_commitment(commitment, value, blinding, params)

    def test_multiple_commitments(self):
        """Create and verify multiple commitments."""
        params = setup_curve()
        values = [0, 1, 10, 100, 1000, 10000]

        commitments = []
        for value in values:
            c, b = commit(value, params=params)
            commitments.append((c, b, value))

        # Verify all
        for c, b, v in commitments:
            assert verify_commitment(c, v, b, params)

    def test_homomorphic_chain(self):
        """Chain of homomorphic additions."""
        params = setup_curve()

        # Create commitments
        c1, b1 = commit(10, params=params)
        c2, b2 = commit(20, params=params)
        c3, b3 = commit(30, params=params)

        # Add incrementally
        c12 = add_commitments(c1, c2, params)
        c123 = add_commitments(c12, c3, params)

        # Verify sum
        assert verify_commitment(c123, 60, b1 + b2 + b3, params)


# ============================================================================
# REVIEW CHECKLIST
# ============================================================================

"""
REVIEW CHECKLIST FOR CRYPTOGRAPHIC EXPERT:

1. Curve Setup:
   ✓ Is secp256k1 NID correct?
   ✓ Is generator H derived correctly via hash-to-point?
   ✓ Are G and H guaranteed to have unknown discrete log?
   ✓ Is group order validation sufficient?

2. Commitment Creation:
   ✓ Is the formula C = value*G + blinding*H implemented correctly?
   ✓ Is input validation comprehensive?
   ✓ Is randomness generation cryptographically secure?
   ✓ Are values and blinding reduced modulo order?

3. Commitment Verification:
   ✓ Is verification constant-time?
   ✓ Does it leak information on failure?
   ✓ Is point deserialization safe?
   ✓ Are edge cases handled correctly?

4. Homomorphic Operations:
   ✓ Is addition formula correct?
   ✓ Are blinding factors combined correctly?
   ✓ Does overflow handling work?

5. Security Properties:
   ✓ Are commitments hiding (random blinding)?
   ✓ Are commitments binding (can't change value)?
   ✓ Is Nothing-Up-My-Sleeve generator derivation sound?

6. Error Handling:
   ✓ Are all error paths tested?
   ✓ Do errors prevent information leakage?
   ✓ Are exceptions appropriate?

7. Performance:
   ✓ Does commit meet 3-7ms target?
   ✓ Does verify meet 2-5ms target?
   ✓ Is caching appropriate?

KNOWN LIMITATIONS:
- petlib constant-time guarantees not verified
- No formal proof of security
- Fork-safety relies on RandomnessSource
- Performance depends on hardware

RECOMMENDED NEXT STEPS:
1. Verify petlib uses constant-time comparison
2. Audit RandomnessSource for fork safety
3. Add fuzz testing for edge cases
4. Benchmark on production hardware
5. Get formal crypto review
"""

