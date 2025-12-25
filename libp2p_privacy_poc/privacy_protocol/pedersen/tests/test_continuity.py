"""Tests for identity continuity proofs"""

import hashlib

import pytest
from petlib.bn import Bn

try:
    from privacy_protocol.pedersen.continuity import (
        generate_continuity_proof,
        verify_continuity_proof,
        extract_identity_from_two_proofs,
        get_random_scalar_mod_order,
        g,
        h,
        order,
    )
    from privacy_protocol.types import ProofContext
except ModuleNotFoundError:
    from ..continuity import (
        generate_continuity_proof,
        verify_continuity_proof,
        extract_identity_from_two_proofs,
        get_random_scalar_mod_order,
        g,
        h,
        order,
    )
    from ...types import ProofContext


class TestContinuityProof:
    """Test continuity proof generation and verification"""

    def test_valid_continuity_proof_verifies(self):
        """Valid continuity proof passes verification"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)

        ctx = ProofContext(
            peer_id="test_peer",
            session_id="continuity_test",
            metadata={},
            timestamp=1000.0,
        )
        ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()

        proof = generate_continuity_proof(
            identity_scalar=identity_scalar,
            blinding_1=blinding_1,
            blinding_2=blinding_2,
            ctx_hash=ctx_hash,
        )

        assert verify_continuity_proof(proof)

    def test_same_identity_across_sessions(self):
        """Continuity proof works across multiple session pairs"""
        identity_scalar = Bn.from_num(42)

        for i in range(5):
            blinding_1 = Bn.from_num(100 + i * 10)
            blinding_2 = Bn.from_num(200 + i * 10)

            ctx = ProofContext(
                peer_id="test_peer",
                session_id=f"pair_{i}",
                metadata={},
                timestamp=1000.0 + i,
            )
            ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()

            proof = generate_continuity_proof(
                identity_scalar, blinding_1, blinding_2, ctx_hash
            )

            assert verify_continuity_proof(proof)

    def test_different_identity_different_commitments(self):
        """Different identities produce different commitment pairs"""
        id1 = Bn.from_num(42)
        id2 = Bn.from_num(99)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof1 = generate_continuity_proof(id1, blinding_1, blinding_2, ctx_hash)
        proof2 = generate_continuity_proof(id2, blinding_1, blinding_2, ctx_hash)

        assert verify_continuity_proof(proof1)
        assert verify_continuity_proof(proof2)

        c1_1 = proof1.public_inputs["commitment_1"]
        c1_2 = proof2.public_inputs["commitment_1"]
        assert c1_1 != c1_2


class TestContinuityTampering:
    """Test tamper resistance"""

    def test_tampered_commitment_1_fails(self):
        """Tampered first commitment fails"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        proof.public_inputs["commitment_1"] = b"\x02" + b"\xff" * 32

        assert not verify_continuity_proof(proof)

    def test_tampered_commitment_2_fails(self):
        """Tampered second commitment fails"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        proof.public_inputs["commitment_2"] = b"\x02" + b"\xff" * 32

        assert not verify_continuity_proof(proof)

    def test_tampered_challenge_fails(self):
        """Tampered challenge fails"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        proof.challenge = b"\xff" * 32

        assert not verify_continuity_proof(proof)

    def test_tampered_response_fails(self):
        """Tampered response fails"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        proof.response = b"\xff" * 96

        assert not verify_continuity_proof(proof)

    def test_swapped_commitments_fails(self):
        """Swapping C1 and C2 fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        c1 = proof.public_inputs["commitment_1"]
        c2 = proof.public_inputs["commitment_2"]
        proof.public_inputs["commitment_1"] = c2
        proof.public_inputs["commitment_2"] = c1

        assert not verify_continuity_proof(proof)

    def test_wrong_context_hash_fails(self):
        """Proof with wrong context hash fails"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        proof.public_inputs["ctx_hash"] = b"\xbb" * 32

        assert not verify_continuity_proof(proof)

    def test_invalid_commitment_length_fails(self):
        """Invalid commitment length fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        proof.commitment = b"\x00" * 10

        assert not verify_continuity_proof(proof)

    def test_invalid_response_length_fails(self):
        """Invalid response length fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        proof.response = b"\x00" * 10

        assert not verify_continuity_proof(proof)


class TestContinuityExtraction:
    """Test special soundness (extraction)"""

    def test_extraction_with_fixed_nonces(self, monkeypatch):
        """Extract identity scalar from two proofs with same nonces"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)

        fixed_nonces = [Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)]
        nonce_counter = {"idx": 0}

        def mock_random():
            value = fixed_nonces[nonce_counter["idx"] % len(fixed_nonces)]
            nonce_counter["idx"] += 1
            return value

        try:
            import privacy_protocol.pedersen.continuity as cont_module
        except ModuleNotFoundError:
            from .. import continuity as cont_module

        monkeypatch.setattr(cont_module, "get_random_scalar_mod_order", mock_random)

        ctx_hash = b"\xaa" * 32
        proof1 = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        nonce_counter["idx"] = 0
        ctx_hash2 = b"\xbb" * 32
        proof2 = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash2
        )

        assert verify_continuity_proof(proof1)
        assert verify_continuity_proof(proof2)

        c1 = Bn.from_binary(proof1.challenge)
        c2 = Bn.from_binary(proof2.challenge)
        assert c1 != c2

        success, extracted_id = extract_identity_from_two_proofs(proof1, proof2)

        assert success
        assert extracted_id == identity_scalar

    def test_extraction_fails_with_different_commitments(self):
        """Extraction fails if commitments differ"""
        identity_scalar = Bn.from_num(42)
        blinding_1a = Bn.from_num(100)
        blinding_2a = Bn.from_num(200)
        blinding_1b = Bn.from_num(111)
        blinding_2b = Bn.from_num(222)

        ctx_hash1 = b"\xaa" * 32
        ctx_hash2 = b"\xbb" * 32

        proof1 = generate_continuity_proof(
            identity_scalar, blinding_1a, blinding_2a, ctx_hash1
        )
        proof2 = generate_continuity_proof(
            identity_scalar, blinding_1b, blinding_2b, ctx_hash2
        )

        assert verify_continuity_proof(proof1)
        assert verify_continuity_proof(proof2)

        success, _ = extract_identity_from_two_proofs(proof1, proof2)
        assert not success

    def test_extraction_fails_with_same_challenge(self, monkeypatch):
        """Extraction fails if challenges are identical"""
        identity_scalar = Bn.from_num(42)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)

        fixed_nonces = [Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)]
        nonce_counter = {"idx": 0}

        def mock_random():
            value = fixed_nonces[nonce_counter["idx"] % len(fixed_nonces)]
            nonce_counter["idx"] += 1
            return value

        try:
            import privacy_protocol.pedersen.continuity as cont_module
        except ModuleNotFoundError:
            from .. import continuity as cont_module

        monkeypatch.setattr(cont_module, "get_random_scalar_mod_order", mock_random)

        ctx_hash = b"\xaa" * 32
        proof1 = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        nonce_counter["idx"] = 0
        proof2 = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )

        assert verify_continuity_proof(proof1)
        assert verify_continuity_proof(proof2)

        c1 = Bn.from_binary(proof1.challenge)
        c2 = Bn.from_binary(proof2.challenge)
        assert c1 == c2

        success, _ = extract_identity_from_two_proofs(proof1, proof2)
        assert not success


class TestContinuityEdgeCases:
    """Test edge cases"""

    def test_zero_identity_scalar_works(self):
        """Zero identity scalar works"""
        identity_scalar = Bn.from_num(0)
        blinding_1 = Bn.from_num(100)
        blinding_2 = Bn.from_num(200)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )
        assert verify_continuity_proof(proof)

    def test_same_blinding_works(self):
        """Same blinding for both commitments works (edge case)"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(100)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding, blinding, ctx_hash
        )
        assert verify_continuity_proof(proof)

        c1 = proof.public_inputs["commitment_1"]
        c2 = proof.public_inputs["commitment_2"]
        assert c1 == c2

    def test_large_scalars_work(self):
        """Large scalars near curve order work"""
        identity_scalar = order - Bn.from_num(1)
        blinding_1 = order - Bn.from_num(2)
        blinding_2 = order - Bn.from_num(3)
        ctx_hash = b"\xaa" * 32

        proof = generate_continuity_proof(
            identity_scalar, blinding_1, blinding_2, ctx_hash
        )
        assert verify_continuity_proof(proof)


class TestContinuitySanity:
    """Light sanity checks for parameters"""

    def test_generators_distinct(self):
        """Generators are distinct"""
        assert g != h

    def test_random_scalar_source_returns_int(self):
        """Random scalar source returns int"""
        value = get_random_scalar_mod_order()
        assert isinstance(value, int)
