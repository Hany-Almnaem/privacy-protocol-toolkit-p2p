"""Tests for session unlinkability proofs"""

import hashlib

import pytest
from petlib.bn import Bn

try:
    from privacy_protocol.pedersen.unlinkability import (
        generate_unlinkability_proof,
        verify_unlinkability_proof,
        compute_session_tag,
        check_unlinkability,
        order
    )
    from privacy_protocol.types import ProofContext
    from privacy_protocol.statements import StatementType
except ModuleNotFoundError:
    from ..unlinkability import (
        generate_unlinkability_proof,
        verify_unlinkability_proof,
        compute_session_tag,
        check_unlinkability,
        order
    )
    from ...types import ProofContext
    from ...statements import StatementType


class TestSessionTagComputation:
    """Test session tag computation"""

    def test_tag_deterministic(self):
        """Same inputs produce same tag"""
        commitment = b"\x02" + b"\xaa" * 32
        ctx_hash = b"\xbb" * 32

        tag1 = compute_session_tag(commitment, ctx_hash)
        tag2 = compute_session_tag(commitment, ctx_hash)

        assert tag1 == tag2
        assert len(tag1) == 32

    def test_different_context_different_tag(self):
        """Different context produces different tag"""
        commitment = b"\x02" + b"\xaa" * 32
        ctx1 = b"\xbb" * 32
        ctx2 = b"\xcc" * 32

        tag1 = compute_session_tag(commitment, ctx1)
        tag2 = compute_session_tag(commitment, ctx2)

        assert tag1 != tag2

    def test_different_commitment_different_tag(self):
        """Different commitment produces different tag"""
        commitment1 = b"\x02" + b"\xaa" * 32
        commitment2 = b"\x02" + b"\xbb" * 32
        ctx_hash = b"\xcc" * 32

        tag1 = compute_session_tag(commitment1, ctx_hash)
        tag2 = compute_session_tag(commitment2, ctx_hash)

        assert tag1 != tag2


class TestUnlinkabilityProof:
    """Test unlinkability proof generation and verification"""

    def test_valid_unlinkability_proof_verifies(self):
        """Valid unlinkability proof passes verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)

        ctx = ProofContext(
            peer_id="test_peer",
            session_id="session_1",
            metadata={"topic": "test"},
            timestamp=1000.0
        )
        ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()

        proof = generate_unlinkability_proof(
            identity_scalar=identity_scalar,
            blinding=blinding,
            ctx_hash=ctx_hash
        )

        assert verify_unlinkability_proof(proof)

    def test_same_identity_different_context_unlinkable(self):
        """Same identity with different contexts produces unlinkable sessions"""
        identity_scalar = Bn.from_num(42)

        blinding1 = Bn.from_num(100)
        ctx1 = ProofContext(
            peer_id="test_peer",
            session_id="session_1",
            metadata={"topic": "topic_a"},
            timestamp=1000.0
        )
        ctx_hash1 = hashlib.sha256(ctx1.to_bytes()).digest()
        proof1 = generate_unlinkability_proof(identity_scalar, blinding1, ctx_hash1)

        blinding2 = Bn.from_num(200)
        ctx2 = ProofContext(
            peer_id="test_peer",
            session_id="session_2",
            metadata={"topic": "topic_b"},
            timestamp=2000.0
        )
        ctx_hash2 = hashlib.sha256(ctx2.to_bytes()).digest()
        proof2 = generate_unlinkability_proof(identity_scalar, blinding2, ctx_hash2)

        assert verify_unlinkability_proof(proof1)
        assert verify_unlinkability_proof(proof2)

        assert check_unlinkability(proof1, proof2)

        tag1 = proof1.public_inputs["tag"]
        tag2 = proof2.public_inputs["tag"]
        assert tag1 != tag2

        c1 = proof1.public_inputs["commitment"]
        c2 = proof2.public_inputs["commitment"]
        assert c1 != c2

    def test_reused_context_produces_same_tag(self):
        """Reusing context produces distinct tags due to commitment differences"""
        identity_scalar = Bn.from_num(42)

        ctx = ProofContext(
            peer_id="test_peer",
            session_id="session_1",
            metadata={},
            timestamp=1000.0
        )
        ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()

        blinding1 = Bn.from_num(100)
        blinding2 = Bn.from_num(200)

        proof1 = generate_unlinkability_proof(identity_scalar, blinding1, ctx_hash)
        proof2 = generate_unlinkability_proof(identity_scalar, blinding2, ctx_hash)

        assert verify_unlinkability_proof(proof1)
        assert verify_unlinkability_proof(proof2)

        c1 = proof1.public_inputs["commitment"]
        c2 = proof2.public_inputs["commitment"]
        assert c1 != c2

        tag1 = proof1.public_inputs["tag"]
        tag2 = proof2.public_inputs["tag"]
        assert tag1 != tag2

    def test_peer_id_not_in_public_inputs(self):
        """Peer ID is not leaked in public inputs"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)

        peer_id = "12D3KooWSecretPeerID"
        ctx = ProofContext(
            peer_id=peer_id,
            session_id="session_1",
            metadata={},
            timestamp=1000.0
        )
        ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        serialized = proof.serialize()

        assert peer_id.encode() not in serialized

        public_inputs_str = str(proof.public_inputs)
        assert peer_id not in public_inputs_str


class TestUnlinkabilityTampering:
    """Test tamper resistance"""

    def test_tampered_tag_fails(self):
        """Tampered session tag fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.public_inputs["tag"] = b"\xff" * 32

        assert not verify_unlinkability_proof(proof)

    def test_tampered_commitment_fails(self):
        """Tampered commitment fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.public_inputs["commitment"] = b"\x02" + b"\xff" * 32

        assert not verify_unlinkability_proof(proof)

    def test_tampered_challenge_fails(self):
        """Tampered challenge fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.challenge = b"\xff" * 32

        assert not verify_unlinkability_proof(proof)

    def test_tampered_response_fails(self):
        """Tampered response fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.response = b"\xff" * 64

        assert not verify_unlinkability_proof(proof)

    def test_wrong_context_hash_fails(self):
        """Proof with wrong context hash fails"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.public_inputs["ctx_hash"] = b"\xbb" * 32

        assert not verify_unlinkability_proof(proof)

    def test_invalid_commitment_bytes_fails(self):
        """Invalid commitment bytes fail verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.public_inputs["commitment"] = b"\x01" * 10

        assert not verify_unlinkability_proof(proof)

    def test_invalid_response_length_fails(self):
        """Invalid response length fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.response = b"\x00" * 10

        assert not verify_unlinkability_proof(proof)

    def test_wrong_statement_type_fails(self):
        """Wrong statement type fails verification"""
        identity_scalar = Bn.from_num(42)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)

        proof.public_inputs["statement_type"] = StatementType.ANON_SET_MEMBERSHIP.value

        assert not verify_unlinkability_proof(proof)


class TestUnlinkabilityEdgeCases:
    """Test edge cases"""

    def test_zero_identity_scalar_works(self):
        """Zero identity scalar works (edge case)"""
        identity_scalar = Bn.from_num(0)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)
        assert verify_unlinkability_proof(proof)

    def test_large_identity_scalar_works(self):
        """Large identity scalar works"""
        identity_scalar = order - Bn.from_num(1)
        blinding = Bn.from_num(123)
        ctx_hash = b"\xaa" * 32

        proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)
        assert verify_unlinkability_proof(proof)

    def test_multiple_sessions_same_identity(self):
        """Multiple sessions with same identity all verify"""
        identity_scalar = Bn.from_num(42)

        proofs = []
        for i in range(10):
            blinding = Bn.from_num(100 + i)
            ctx = ProofContext(
                peer_id="test_peer",
                session_id=f"session_{i}",
                metadata={},
                timestamp=1000.0 + i
            )
            ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()
            proof = generate_unlinkability_proof(identity_scalar, blinding, ctx_hash)
            proofs.append(proof)

        assert all(verify_unlinkability_proof(p) for p in proofs)

        tags = [p.public_inputs["tag"] for p in proofs]
        assert len(set(tags)) == 10


class TestUnlinkabilityChecks:
    """Test unlinkability checks"""

    def test_check_unlinkability_invalid_proof_returns_false(self):
        """Invalid proof in pair fails unlinkability check"""
        identity_scalar = Bn.from_num(42)

        blinding1 = Bn.from_num(100)
        ctx_hash1 = b"\x11" * 32
        proof1 = generate_unlinkability_proof(identity_scalar, blinding1, ctx_hash1)

        blinding2 = Bn.from_num(200)
        ctx_hash2 = b"\x22" * 32
        proof2 = generate_unlinkability_proof(identity_scalar, blinding2, ctx_hash2)

        proof2.public_inputs["tag"] = b"\x00" * 32

        assert not check_unlinkability(proof1, proof2)

    def test_check_unlinkability_same_context_returns_false(self):
        """Same context is not considered unlinkable"""
        identity_scalar = Bn.from_num(42)
        ctx_hash = b"\x33" * 32

        proof1 = generate_unlinkability_proof(identity_scalar, Bn.from_num(101), ctx_hash)
        proof2 = generate_unlinkability_proof(identity_scalar, Bn.from_num(202), ctx_hash)

        assert verify_unlinkability_proof(proof1)
        assert verify_unlinkability_proof(proof2)

        assert not check_unlinkability(proof1, proof2)
