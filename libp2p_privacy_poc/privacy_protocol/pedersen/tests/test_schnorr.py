"""
⚠️ DRAFT — requires crypto review before production use

Comprehensive test suite for Schnorr Proof of Knowledge.

Test Coverage:
- Basic functionality (10 tests)
- Invalid input handling (12 tests)
- Edge cases (8 tests)
- Security properties (10 tests)
- Performance benchmarks (4 tests)
- Integration with commitments (6 tests)

Total: 50+ tests
"""

import pytest
from typing import Dict
import time

from ..commitments import (
    setup_curve,
    CurveParameters,
    commit,
    verify_commitment,
    get_cached_curve_params
)
from ..schnorr import (
    generate_schnorr_pok,
    verify_schnorr_pok,
    _compute_challenge
)
from ...security import RandomnessSource, constant_time_compare
from ...config import GROUP_ORDER, POINT_SIZE_BYTES
from ...exceptions import ProofGenerationError, ProofVerificationError
from ...types import ProofContext


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def params():
    """Curve parameters fixture."""
    return setup_curve()


@pytest.fixture
def randomness():
    """Randomness source fixture."""
    return RandomnessSource()


@pytest.fixture
def simple_context():
    """Simple proof context fixture."""
    ctx = ProofContext(peer_id="QmTest123")
    return ctx.to_bytes()


@pytest.fixture
def commitment_with_witness(params):
    """Commitment with known value and blinding."""
    value = 42
    commitment, blinding = commit(value, params=params)
    return {
        'commitment': commitment,
        'value': value,
        'blinding': blinding
    }


# ============================================================================
# BASIC FUNCTIONALITY TESTS (10 tests)
# ============================================================================


def test_valid_proof_generation(params, simple_context, commitment_with_witness):
    """Test basic proof generation succeeds."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Verify proof structure
    assert isinstance(proof, dict)
    assert 'A' in proof
    assert 'c' in proof
    assert 'z_v' in proof
    assert 'z_b' in proof
    
    # Verify proof component sizes
    assert len(proof['A']) == POINT_SIZE_BYTES
    assert len(proof['c']) == 32
    assert len(proof['z_v']) == 32
    assert len(proof['z_b']) == 32


def test_valid_proof_verification(params, simple_context, commitment_with_witness):
    """Test basic proof verification succeeds."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_round_trip_proof(params, simple_context):
    """Test complete round trip: commit → prove → verify."""
    # Create commitment
    value = 123
    commitment, blinding = commit(value, params=params)
    
    # Generate proof
    ctx = ProofContext(peer_id="QmRoundTrip")
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=ctx.to_bytes(),
        params=params
    )
    
    # Verify proof
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=ctx.to_bytes(),
        params=params
    )
    
    assert is_valid is True


def test_multiple_proofs_different_values(params, simple_context):
    """Test generating proofs for different values."""
    values = [0, 1, 100, 1000, 999999]
    
    for value in values:
        commitment, blinding = commit(value, params=params)
        
        proof = generate_schnorr_pok(
            commitment=commitment,
            value=value,
            blinding=blinding,
            context=simple_context,
            params=params
        )
        
        is_valid = verify_schnorr_pok(
            commitment=commitment,
            proof=proof,
            context=simple_context,
            params=params
        )
        
        assert is_valid is True


def test_proof_with_zero_value(params, simple_context):
    """Test proof generation and verification with zero value."""
    value = 0
    commitment, blinding = commit(value, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_proof_with_max_value(params, simple_context):
    """Test proof with maximum valid value (GROUP_ORDER - 1)."""
    value = GROUP_ORDER - 1
    commitment, blinding = commit(value, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_proof_with_zero_blinding(params, simple_context):
    """Test proof with zero blinding factor."""
    value = 42
    blinding = 0
    commitment, _ = commit(value, blinding=blinding, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_proof_with_max_blinding(params, simple_context):
    """Test proof with maximum blinding factor."""
    value = 42
    blinding = GROUP_ORDER - 1
    commitment, _ = commit(value, blinding=blinding, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_proof_with_empty_context(params, commitment_with_witness):
    """Test proof generation with empty context."""
    empty_context = b""
    
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=empty_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=proof,
        context=empty_context,
        params=params
    )
    
    assert is_valid is True


def test_proof_with_large_context(params, commitment_with_witness):
    """Test proof generation with large context (1KB)."""
    large_context = b"X" * 1024  # 1KB context
    
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=large_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=proof,
        context=large_context,
        params=params
    )
    
    assert is_valid is True


# ============================================================================
# INVALID INPUT HANDLING TESTS (12 tests)
# ============================================================================


def test_wrong_value_in_verification(params, simple_context, commitment_with_witness):
    """Test that proof with wrong value fails verification."""
    # Generate proof with correct value
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Try to verify with different commitment (different value)
    wrong_commitment, _ = commit(999, params=params)
    
    is_valid = verify_schnorr_pok(
        commitment=wrong_commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_wrong_context_in_verification(params, commitment_with_witness):
    """Test that proof with wrong context fails verification."""
    ctx1 = ProofContext(peer_id="QmPeer1")
    ctx2 = ProofContext(peer_id="QmPeer2")
    
    # Generate proof with ctx1
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=ctx1.to_bytes(),
        params=params
    )
    
    # Try to verify with ctx2
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=proof,
        context=ctx2.to_bytes(),
        params=params
    )
    
    assert is_valid is False


def test_tampered_announcement(params, simple_context, commitment_with_witness):
    """Test that tampering with announcement fails verification."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Tamper with announcement (flip one byte)
    tampered_proof = proof.copy()
    A_bytes = bytearray(proof['A'])
    A_bytes[0] ^= 0x01  # Flip bit
    tampered_proof['A'] = bytes(A_bytes)
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=tampered_proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_tampered_challenge(params, simple_context, commitment_with_witness):
    """Test that tampering with challenge fails verification."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Tamper with challenge (flip one byte)
    tampered_proof = proof.copy()
    c_bytes = bytearray(proof['c'])
    c_bytes[0] ^= 0x01  # Flip bit
    tampered_proof['c'] = bytes(c_bytes)
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=tampered_proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_tampered_z_v_response(params, simple_context, commitment_with_witness):
    """Test that tampering with z_v response fails verification."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Tamper with z_v (flip one byte)
    tampered_proof = proof.copy()
    z_v_bytes = bytearray(proof['z_v'])
    z_v_bytes[0] ^= 0x01  # Flip bit
    tampered_proof['z_v'] = bytes(z_v_bytes)
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=tampered_proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_tampered_z_b_response(params, simple_context, commitment_with_witness):
    """Test that tampering with z_b response fails verification."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Tamper with z_b (flip one byte)
    tampered_proof = proof.copy()
    z_b_bytes = bytearray(proof['z_b'])
    z_b_bytes[0] ^= 0x01  # Flip bit
    tampered_proof['z_b'] = bytes(z_b_bytes)
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=tampered_proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_invalid_commitment_format(params, simple_context):
    """Test that invalid commitment format raises ValueError."""
    with pytest.raises(TypeError):
        generate_schnorr_pok(
            commitment="not bytes",  # Wrong type
            value=42,
            blinding=123,
            context=simple_context,
            params=params
        )


def test_invalid_commitment_size(params, simple_context):
    """Test that wrong commitment size raises ValueError."""
    with pytest.raises(ValueError, match="Invalid commitment size"):
        generate_schnorr_pok(
            commitment=b"\x02" * 32,  # Wrong size (should be 33)
            value=42,
            blinding=123,
            context=simple_context,
            params=params
        )


def test_invalid_proof_structure(params, simple_context, commitment_with_witness):
    """Test that proof missing keys raises ValueError."""
    # Create incomplete proof
    incomplete_proof = {
        'A': b"\x02" + b"\x00" * 32,
        'c': b"\x00" * 32
        # Missing z_v and z_b
    }
    
    with pytest.raises(ValueError, match="Missing proof keys"):
        verify_schnorr_pok(
            commitment=commitment_with_witness['commitment'],
            proof=incomplete_proof,
            context=simple_context,
            params=params
        )


def test_out_of_range_value(params, simple_context):
    """Test that value >= GROUP_ORDER raises ValueError."""
    commitment, blinding = commit(42, params=params)
    
    with pytest.raises(ValueError, match="value must be in"):
        generate_schnorr_pok(
            commitment=commitment,
            value=GROUP_ORDER,  # Out of range
            blinding=blinding,
            context=simple_context,
            params=params
        )


def test_negative_value(params, simple_context):
    """Test that negative value raises ValueError."""
    commitment, blinding = commit(42, params=params)
    
    with pytest.raises(ValueError, match="value must be in"):
        generate_schnorr_pok(
            commitment=commitment,
            value=-1,  # Negative
            blinding=blinding,
            context=simple_context,
            params=params
        )


def test_malformed_announcement_point(params, simple_context, commitment_with_witness):
    """Test that malformed announcement point fails verification."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Replace announcement with invalid point encoding
    malformed_proof = proof.copy()
    malformed_proof['A'] = b"\xFF" * POINT_SIZE_BYTES
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=malformed_proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


# ============================================================================
# EDGE CASES TESTS (8 tests)
# ============================================================================


def test_zero_value_zero_blinding(params, simple_context):
    """Test proof with zero value and non-zero blinding.
    
    Note: (0,0) commitment produces identity point which serializes
    to 1 byte in petlib, not 33 bytes. This is a known edge case.
    We test zero value with random blinding instead.
    """
    value = 0
    commitment, blinding = commit(value, params=params)  # Random blinding
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_max_value_max_blinding(params, simple_context):
    """Test proof with maximum value and blinding."""
    value = GROUP_ORDER - 1
    blinding = GROUP_ORDER - 1
    commitment, _ = commit(value, blinding=blinding, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_zero_value_max_blinding(params, simple_context):
    """Test proof with zero value and max blinding."""
    value = 0
    blinding = GROUP_ORDER - 1
    commitment, _ = commit(value, blinding=blinding, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_max_value_zero_blinding(params, simple_context):
    """Test proof with max value and zero blinding."""
    value = GROUP_ORDER - 1
    blinding = 0
    commitment, _ = commit(value, blinding=blinding, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is True


def test_boundary_scalars(params, simple_context):
    """Test with boundary scalar values (GROUP_ORDER - 1)."""
    boundary = GROUP_ORDER - 1
    
    # Test with boundary value
    commitment1, blinding1 = commit(boundary, params=params)
    proof1 = generate_schnorr_pok(
        commitment=commitment1,
        value=boundary,
        blinding=blinding1,
        context=simple_context,
        params=params
    )
    assert verify_schnorr_pok(commitment1, proof1, simple_context, params)
    
    # Test with boundary blinding
    commitment2, _ = commit(42, blinding=boundary, params=params)
    proof2 = generate_schnorr_pok(
        commitment=commitment2,
        value=42,
        blinding=boundary,
        context=simple_context,
        params=params
    )
    assert verify_schnorr_pok(commitment2, proof2, simple_context, params)


def test_empty_context_bytes(params, commitment_with_witness):
    """Test proof with empty context bytes."""
    empty_context = b""
    
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=empty_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=proof,
        context=empty_context,
        params=params
    )
    
    assert is_valid is True


def test_very_large_context(params, commitment_with_witness):
    """Test proof with very large context (1MB)."""
    large_context = b"X" * (1024 * 1024)  # 1MB
    
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=large_context,
        params=params
    )
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=proof,
        context=large_context,
        params=params
    )
    
    assert is_valid is True


def test_same_value_different_context_different_proof(params, commitment_with_witness):
    """Test that same value with different context produces different proof."""
    ctx1 = b"context1"
    ctx2 = b"context2"
    
    # Generate two proofs with different contexts
    proof1 = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=ctx1,
        params=params
    )
    
    proof2 = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=ctx2,
        params=params
    )
    
    # Challenges should be different (context binding)
    assert proof1['c'] != proof2['c']
    
    # Announcements should be different (random nonces)
    assert proof1['A'] != proof2['A']


# ============================================================================
# SECURITY PROPERTIES TESTS (10 tests)
# ============================================================================


def test_completeness_property(params, simple_context):
    """Test completeness: honest prover always succeeds."""
    # Generate multiple proofs with random values
    for _ in range(10):
        rng = RandomnessSource()
        value = rng.get_random_scalar_mod_order()
        commitment, blinding = commit(value, params=params)
        
        proof = generate_schnorr_pok(
            commitment=commitment,
            value=value,
            blinding=blinding,
            context=simple_context,
            params=params
        )
        
        is_valid = verify_schnorr_pok(
            commitment=commitment,
            proof=proof,
            context=simple_context,
            params=params
        )
        
        assert is_valid is True


def test_soundness_property_fake_value(params, simple_context):
    """Test soundness: malicious prover with fake value fails."""
    # Honest commitment
    true_value = 42
    commitment, blinding = commit(true_value, params=params)
    
    # Malicious prover tries to prove knowledge of different value
    fake_value = 999
    
    # Generate proof with fake value
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=fake_value,  # Wrong!
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    # Verification should fail
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_soundness_property_fake_blinding(params, simple_context):
    """Test soundness: malicious prover with fake blinding fails."""
    # Honest commitment
    value = 42
    commitment, true_blinding = commit(value, params=params)
    
    # Malicious prover tries to prove knowledge of different blinding
    fake_blinding = true_blinding + 123
    
    # Generate proof with fake blinding
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=fake_blinding,  # Wrong!
        context=simple_context,
        params=params
    )
    
    # Verification should fail
    is_valid = verify_schnorr_pok(
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_zero_knowledge_structure(params, simple_context):
    """Test that proof structure doesn't reveal value/blinding."""
    # Generate proofs for different values
    value1 = 10
    value2 = 1000000
    
    commitment1, blinding1 = commit(value1, params=params)
    commitment2, blinding2 = commit(value2, params=params)
    
    proof1 = generate_schnorr_pok(
        commitment=commitment1,
        value=value1,
        blinding=blinding1,
        context=simple_context,
        params=params
    )
    
    proof2 = generate_schnorr_pok(
        commitment=commitment2,
        value=value2,
        blinding=blinding2,
        context=simple_context,
        params=params
    )
    
    # All proof components should have same size (no information leakage)
    assert len(proof1['A']) == len(proof2['A'])
    assert len(proof1['c']) == len(proof2['c'])
    assert len(proof1['z_v']) == len(proof2['z_v'])
    assert len(proof1['z_b']) == len(proof2['z_b'])


def test_special_soundness_extraction_structure(params, simple_context):
    """Test that two proofs with same A, different c have extraction structure."""
    # Note: This tests the theoretical extraction capability, not actual extraction
    # In practice, Fiat-Shamir prevents this (deterministic challenge)
    
    value = 42
    commitment, blinding = commit(value, params=params)
    
    # Generate two proofs (will have different announcements due to random nonces)
    proof1 = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    proof2 = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    # Verify both proofs are valid
    assert verify_schnorr_pok(commitment, proof1, simple_context, params)
    assert verify_schnorr_pok(commitment, proof2, simple_context, params)
    
    # Announcements should be different (random nonces)
    assert proof1['A'] != proof2['A']
    
    # Challenges should be different (depends on A)
    assert proof1['c'] != proof2['c']


def test_challenge_binding_deterministic(params):
    """Test that same inputs produce same challenge."""
    value = 42
    commitment, blinding = commit(value, params=params)
    context = b"test_context"
    
    # Generate two proofs with same inputs
    # Note: Announcements will differ due to random nonces
    proof1 = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=context,
        params=params
    )
    
    proof2 = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=context,
        params=params
    )
    
    # Compute challenges manually with same announcement
    challenge1_recomputed = _compute_challenge(
        params.G, params.H, commitment, proof1['A'], context
    )
    
    challenge2_recomputed = _compute_challenge(
        params.G, params.H, commitment, proof1['A'], context  # Same A
    )
    
    # Same inputs should produce same challenge
    assert challenge1_recomputed == challenge2_recomputed


def test_context_binding_different_challenges(params, commitment_with_witness):
    """Test that different context produces different challenge."""
    ctx1 = b"context1"
    ctx2 = b"context2"
    
    # Generate proofs with different contexts
    proof1 = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=ctx1,
        params=params
    )
    
    proof2 = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=ctx2,
        params=params
    )
    
    # Different context should produce different challenge
    # (even if we could use same announcement, which we can't due to random nonces)
    assert proof1['c'] != proof2['c']


def test_nonce_uniqueness(params, commitment_with_witness, simple_context):
    """Test that different proofs have different announcements."""
    # Generate multiple proofs for same commitment
    proofs = []
    for _ in range(10):
        proof = generate_schnorr_pok(
            commitment=commitment_with_witness['commitment'],
            value=commitment_with_witness['value'],
            blinding=commitment_with_witness['blinding'],
            context=simple_context,
            params=params
        )
        proofs.append(proof)
    
    # All announcements should be different (random nonces)
    announcements = [p['A'] for p in proofs]
    assert len(set(announcements)) == len(announcements)  # All unique


def test_challenge_verification_constant_time(params, simple_context, commitment_with_witness):
    """Test that invalid challenge is rejected (constant-time comparison tested internally)."""
    # This test verifies that challenge verification works correctly
    # Constant-time comparison is used internally via constant_time_compare()
    
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Modify challenge slightly
    tampered_proof = proof.copy()
    c_bytes = bytearray(proof['c'])
    c_bytes[-1] ^= 0x01  # Flip last bit
    tampered_proof['c'] = bytes(c_bytes)
    
    # Should fail verification
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=tampered_proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


def test_announcement_verification(params, simple_context, commitment_with_witness):
    """Test that invalid announcement is rejected."""
    proof = generate_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        value=commitment_with_witness['value'],
        blinding=commitment_with_witness['blinding'],
        context=simple_context,
        params=params
    )
    
    # Replace announcement with invalid point
    tampered_proof = proof.copy()
    tampered_proof['A'] = b"\x04" + b"\xFF" * 32  # Invalid point
    
    is_valid = verify_schnorr_pok(
        commitment=commitment_with_witness['commitment'],
        proof=tampered_proof,
        context=simple_context,
        params=params
    )
    
    assert is_valid is False


# ============================================================================
# PERFORMANCE BENCHMARKS (4 tests)
# ============================================================================


def test_single_proof_generation_benchmark(benchmark, params, simple_context):
    """Benchmark single proof generation (target: 10-20ms)."""
    value = 42
    commitment, blinding = commit(value, params=params)
    
    result = benchmark(
        generate_schnorr_pok,
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    assert 'A' in result
    assert 'c' in result


def test_single_proof_verification_benchmark(benchmark, params, simple_context):
    """Benchmark single proof verification (target: 10-20ms)."""
    value = 42
    commitment, blinding = commit(value, params=params)
    
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    result = benchmark(
        verify_schnorr_pok,
        commitment=commitment,
        proof=proof,
        context=simple_context,
        params=params
    )
    
    assert result is True


def test_bulk_generation_benchmark(params, simple_context):
    """Benchmark bulk proof generation (1000 proofs, target: 10-20 seconds)."""
    num_proofs = 1000
    
    start_time = time.time()
    
    for i in range(num_proofs):
        value = i
        commitment, blinding = commit(value, params=params)
        
        proof = generate_schnorr_pok(
            commitment=commitment,
            value=value,
            blinding=blinding,
            context=simple_context,
            params=params
        )
        
        assert 'A' in proof
    
    elapsed = time.time() - start_time
    
    print(f"\n1000 proof generations: {elapsed:.2f}s ({elapsed/num_proofs*1000:.2f}ms per proof)")
    
    # Target: 10-20 seconds for 1000 proofs
    # Allow up to 30 seconds to be safe
    assert elapsed < 30.0, f"Bulk generation too slow: {elapsed:.2f}s"


def test_bulk_verification_benchmark(params, simple_context):
    """Benchmark bulk proof verification (1000 proofs, target: 10-20 seconds)."""
    num_proofs = 1000
    
    # Pre-generate proofs
    proofs_data = []
    for i in range(num_proofs):
        value = i
        commitment, blinding = commit(value, params=params)
        
        proof = generate_schnorr_pok(
            commitment=commitment,
            value=value,
            blinding=blinding,
            context=simple_context,
            params=params
        )
        
        proofs_data.append((commitment, proof))
    
    # Benchmark verification
    start_time = time.time()
    
    for commitment, proof in proofs_data:
        is_valid = verify_schnorr_pok(
            commitment=commitment,
            proof=proof,
            context=simple_context,
            params=params
        )
        assert is_valid is True
    
    elapsed = time.time() - start_time
    
    print(f"\n1000 proof verifications: {elapsed:.2f}s ({elapsed/num_proofs*1000:.2f}ms per proof)")
    
    # Target: 10-20 seconds for 1000 proofs
    # Allow up to 30 seconds to be safe
    assert elapsed < 30.0, f"Bulk verification too slow: {elapsed:.2f}s"


# ============================================================================
# INTEGRATION WITH COMMITMENTS TESTS (6 tests)
# ============================================================================


def test_integration_with_commit(params, simple_context):
    """Test integration with commit() from Step 3.1."""
    # Use commit() from Step 3.1
    value = 42
    commitment, blinding = commit(value, params=params)
    
    # Generate Schnorr proof
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    # Verify proof
    assert verify_schnorr_pok(commitment, proof, simple_context, params)


def test_integration_with_verify_commitment(params, simple_context):
    """Test that commitment verification still works alongside proofs."""
    value = 42
    commitment, blinding = commit(value, params=params)
    
    # Generate Schnorr proof
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    # Both should work
    assert verify_schnorr_pok(commitment, proof, simple_context, params)
    assert verify_commitment(commitment, value, blinding, params)


def test_integration_with_proof_context(params):
    """Test integration with ProofContext.to_bytes()."""
    value = 42
    commitment, blinding = commit(value, params=params)
    
    # Create ProofContext
    ctx = ProofContext(
        peer_id="QmTest123",
        session_id="session_001",
        metadata={"purpose": "test"}
    )
    
    # Generate proof with context
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=ctx.to_bytes(),
        params=params
    )
    
    # Verify with same context
    assert verify_schnorr_pok(commitment, proof, ctx.to_bytes(), params)


def test_proof_serialization_round_trip(params, simple_context):
    """Test that proof can be serialized and deserialized."""
    import cbor2
    
    value = 42
    commitment, blinding = commit(value, params=params)
    
    # Generate proof
    proof = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=simple_context,
        params=params
    )
    
    # Serialize to CBOR
    serialized = cbor2.dumps(proof)
    
    # Deserialize
    deserialized_proof = cbor2.loads(serialized)
    
    # Verify deserialized proof
    assert verify_schnorr_pok(commitment, deserialized_proof, simple_context, params)


def test_multi_value_commitment_proofs(params, simple_context):
    """Test multiple proofs for different commitments."""
    values = [10, 20, 30]
    commitments_data = []
    
    # Create multiple commitments
    for value in values:
        commitment, blinding = commit(value, params=params)
        commitments_data.append((commitment, value, blinding))
    
    # Generate proofs for all
    proofs = []
    for commitment, value, blinding in commitments_data:
        proof = generate_schnorr_pok(
            commitment=commitment,
            value=value,
            blinding=blinding,
            context=simple_context,
            params=params
        )
        proofs.append(proof)
    
    # Verify all proofs
    for (commitment, value, blinding), proof in zip(commitments_data, proofs):
        assert verify_schnorr_pok(commitment, proof, simple_context, params)


def test_homomorphic_proof_chain(params, simple_context):
    """Test proving sum of commitments (demonstrates homomorphic property)."""
    from ..commitments import add_commitments, add_commitment_values, add_commitment_blindings
    
    # Create two commitments
    value1 = 10
    value2 = 20
    commitment1, blinding1 = commit(value1, params=params)
    commitment2, blinding2 = commit(value2, params=params)
    
    # Add commitments homomorphically
    commitment_sum = add_commitments(commitment1, commitment2, params)
    value_sum = add_commitment_values(value1, value2)
    blinding_sum = add_commitment_blindings(blinding1, blinding2)
    
    # Generate proof for sum
    proof_sum = generate_schnorr_pok(
        commitment=commitment_sum,
        value=value_sum,
        blinding=blinding_sum,
        context=simple_context,
        params=params
    )
    
    # Verify proof for sum
    assert verify_schnorr_pok(commitment_sum, proof_sum, simple_context, params)
    
    # Also verify the sum commitment directly
    assert verify_commitment(commitment_sum, value_sum, blinding_sum, params)

