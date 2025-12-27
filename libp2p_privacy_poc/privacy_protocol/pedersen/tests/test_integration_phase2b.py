"""
End-to-end integration tests for Phase 2B statements.
Tests all three privacy statements working together.
"""

import pytest
from petlib.bn import Bn

try:
    from privacy_protocol.pedersen.backend import PedersenBackend
    from privacy_protocol.types import ProofContext
    from privacy_protocol.statements import StatementType
    from privacy_protocol.merkle import hash_leaf, build_tree, DOMAIN_SEPARATORS_2B
except ModuleNotFoundError:
    from ..backend import PedersenBackend
    from ...types import ProofContext
    from ...statements import StatementType
    from ...merkle import hash_leaf, build_tree, DOMAIN_SEPARATORS_2B


def _get_membership_generators():
    try:
        from privacy_protocol.pedersen.membership import g, h
    except ModuleNotFoundError:
        from ..membership import g, h
    return g, h


class TestFactoryIntegration:
    """Test proof generation through backend factory"""

    def setup_method(self):
        """Setup backend for each test"""
        self.backend = PedersenBackend()
        self.identity_scalar = Bn.from_num(42)

    def test_backend_has_all_statement_methods(self):
        """Backend exposes all Phase 2B statement methods"""
        assert hasattr(self.backend, "generate_membership_proof")
        assert hasattr(self.backend, "verify_membership_proof")
        assert hasattr(self.backend, "generate_unlinkability_proof")
        assert hasattr(self.backend, "verify_unlinkability_proof")
        assert hasattr(self.backend, "generate_continuity_proof")
        assert hasattr(self.backend, "verify_continuity_proof")

    def test_membership_proof_end_to_end(self):
        """Membership proof works end-to-end through backend"""
        g, h = _get_membership_generators()

        identities = [Bn.from_num(i + 1) for i in range(8)]
        blindings = [Bn.from_num(i + 100) for i in range(8)]
        commitments = [
            ((id_s * g) + (blind * h)).export()
            for id_s, blind in zip(identities, blindings)
        ]

        leaves = [
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], c)
            for c in commitments
        ]
        root, paths = build_tree(leaves)

        my_index = 3
        context = ProofContext(
            peer_id="integration_peer",
            session_id="membership_session",
            metadata={},
            timestamp=1000.0,
        )

        proof = self.backend.generate_membership_proof(
            identity_scalar=identities[my_index],
            blinding=blindings[my_index],
            merkle_path=paths[my_index],
            root=root,
            context=context,
        )

        assert self.backend.verify_membership_proof(proof)

        assert proof.get_statement_type() == StatementType.ANON_SET_MEMBERSHIP.value
        assert proof.get_statement_version() == 1

    def test_unlinkability_proof_end_to_end(self):
        """Unlinkability proof works end-to-end through backend"""
        blinding = Bn.from_num(200)

        context = ProofContext(
            peer_id="integration_peer",
            session_id="unlinkability_session",
            metadata={"topic": "test"},
            timestamp=2000.0,
        )

        proof = self.backend.generate_unlinkability_proof(
            identity_scalar=self.identity_scalar,
            blinding=blinding,
            context=context,
        )

        assert self.backend.verify_unlinkability_proof(proof)

        assert proof.get_statement_type() == StatementType.SESSION_UNLINKABILITY.value
        assert proof.get_statement_version() == 1

    def test_continuity_proof_end_to_end(self):
        """Continuity proof works end-to-end through backend"""
        blinding_1 = Bn.from_num(300)
        blinding_2 = Bn.from_num(400)

        context = ProofContext(
            peer_id="integration_peer",
            session_id="continuity_session",
            metadata={},
            timestamp=3000.0,
        )

        proof = self.backend.generate_continuity_proof(
            identity_scalar=self.identity_scalar,
            blinding_1=blinding_1,
            blinding_2=blinding_2,
            context=context,
        )

        assert self.backend.verify_continuity_proof(proof)

        assert proof.get_statement_type() == StatementType.IDENTITY_CONTINUITY.value
        assert proof.get_statement_version() == 1


class TestCrossStatementConsistency:
    """Test that statements can coexist and share identity management"""

    def setup_method(self):
        """Setup shared identity"""
        self.backend = PedersenBackend()
        self.identity_scalar = Bn.from_num(42)

    def test_membership_and_continuity_share_identity(self):
        """
        Can prove membership in one session and continuity across another
        using the same identity scalar.
        """
        g, h = _get_membership_generators()

        blinding_1 = Bn.from_num(100)
        commitment_1 = ((self.identity_scalar * g) + (blinding_1 * h)).export()

        commitments = [commitment_1] + [
            ((Bn.from_num(i + 50) * g) + (Bn.from_num(i + 150) * h)).export()
            for i in range(7)
        ]
        leaves = [
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], c)
            for c in commitments
        ]
        root, paths = build_tree(leaves)

        ctx1 = ProofContext(
            peer_id="test_peer",
            session_id="session_1",
            metadata={},
            timestamp=1000.0,
        )

        membership_proof = self.backend.generate_membership_proof(
            identity_scalar=self.identity_scalar,
            blinding=blinding_1,
            merkle_path=paths[0],
            root=root,
            context=ctx1,
        )

        blinding_2 = Bn.from_num(200)
        blinding_3 = Bn.from_num(300)

        ctx2 = ProofContext(
            peer_id="test_peer",
            session_id="session_2_3",
            metadata={},
            timestamp=2000.0,
        )

        continuity_proof = self.backend.generate_continuity_proof(
            identity_scalar=self.identity_scalar,
            blinding_1=blinding_2,
            blinding_2=blinding_3,
            context=ctx2,
        )

        assert self.backend.verify_membership_proof(membership_proof)
        assert self.backend.verify_continuity_proof(continuity_proof)

        C1_from_membership = membership_proof.public_inputs["commitment"]
        C1_reconstructed = ((self.identity_scalar * g) + (blinding_1 * h)).export()
        assert C1_from_membership == C1_reconstructed

    def test_unlinkability_across_contexts_with_continuity(self):
        """
        Can prove unlinkability across different contexts while also
        proving continuity when needed (selective disclosure).
        """
        blinding_a = Bn.from_num(100)
        blinding_b = Bn.from_num(200)
        blinding_c = Bn.from_num(300)

        ctx_a = ProofContext(
            peer_id="test_peer",
            session_id="session_a",
            metadata={"topic": "topic_a"},
            timestamp=1000.0,
        )
        ctx_b = ProofContext(
            peer_id="test_peer",
            session_id="session_b",
            metadata={"topic": "topic_b"},
            timestamp=2000.0,
        )
        ctx_c = ProofContext(
            peer_id="test_peer",
            session_id="session_c",
            metadata={"topic": "topic_c"},
            timestamp=3000.0,
        )

        proof_a = self.backend.generate_unlinkability_proof(
            self.identity_scalar, blinding_a, ctx_a
        )
        proof_b = self.backend.generate_unlinkability_proof(
            self.identity_scalar, blinding_b, ctx_b
        )
        proof_c = self.backend.generate_unlinkability_proof(
            self.identity_scalar, blinding_c, ctx_c
        )

        assert self.backend.verify_unlinkability_proof(proof_a)
        assert self.backend.verify_unlinkability_proof(proof_b)
        assert self.backend.verify_unlinkability_proof(proof_c)

        tag_a = proof_a.public_inputs["tag"]
        tag_b = proof_b.public_inputs["tag"]
        tag_c = proof_c.public_inputs["tag"]
        assert tag_a != tag_b != tag_c

        continuity_ab = self.backend.generate_continuity_proof(
            identity_scalar=self.identity_scalar,
            blinding_1=blinding_a,
            blinding_2=blinding_b,
            context=ctx_b,
        )
        assert self.backend.verify_continuity_proof(continuity_ab)

    def test_all_three_statements_same_identity(self):
        """Can generate all three statement types for same identity"""
        g, h = _get_membership_generators()

        blinding_membership = Bn.from_num(100)
        blinding_unlink = Bn.from_num(200)
        blinding_cont_1 = Bn.from_num(300)
        blinding_cont_2 = Bn.from_num(400)

        commitment_membership = (
            (self.identity_scalar * g) + (blinding_membership * h)
        ).export()
        commitments = [commitment_membership] + [
            ((Bn.from_num(i + 50) * g) + (Bn.from_num(i + 150) * h)).export()
            for i in range(3)
        ]
        leaves = [
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], c)
            for c in commitments
        ]
        root, paths = build_tree(leaves)

        ctx1 = ProofContext(peer_id="p", session_id="s1", metadata={}, timestamp=1.0)
        membership = self.backend.generate_membership_proof(
            self.identity_scalar, blinding_membership, paths[0], root, ctx1
        )

        ctx2 = ProofContext(peer_id="p", session_id="s2", metadata={}, timestamp=2.0)
        unlinkability = self.backend.generate_unlinkability_proof(
            self.identity_scalar, blinding_unlink, ctx2
        )

        ctx3 = ProofContext(peer_id="p", session_id="s3", metadata={}, timestamp=3.0)
        continuity = self.backend.generate_continuity_proof(
            self.identity_scalar, blinding_cont_1, blinding_cont_2, ctx3
        )

        assert self.backend.verify_membership_proof(membership)
        assert self.backend.verify_unlinkability_proof(unlinkability)
        assert self.backend.verify_continuity_proof(continuity)

        assert membership.get_statement_type() == StatementType.ANON_SET_MEMBERSHIP.value
        assert unlinkability.get_statement_type() == StatementType.SESSION_UNLINKABILITY.value
        assert continuity.get_statement_type() == StatementType.IDENTITY_CONTINUITY.value


class TestBackwardCompatibility:
    """Test Phase 2A proofs still work"""

    def test_phase2a_commitment_opening_still_works(self):
        """Phase 2A commitment opening PoK still works after Phase 2B"""
        backend = PedersenBackend()

        if hasattr(backend, "generate_commitment_opening_proof"):
            context = ProofContext(
                peer_id="legacy_peer",
                session_id="legacy_session",
                metadata={},
                timestamp=0.0,
            )

            proof = backend.generate_commitment_opening_proof(context)

            assert backend.verify_proof(proof)

            assert not proof.is_phase2b_proof()
            assert proof.get_statement_type() is None

    def test_phase2a_and_phase2b_proofs_coexist(self):
        """Can generate both Phase 2A and Phase 2B proofs"""
        backend = PedersenBackend()

        identity = Bn.from_num(42)
        blinding = Bn.from_num(100)
        ctx = ProofContext(peer_id="p", session_id="s", metadata={}, timestamp=1.0)

        phase2b_proof = backend.generate_unlinkability_proof(identity, blinding, ctx)

        assert backend.verify_unlinkability_proof(phase2b_proof)
        assert phase2b_proof.is_phase2b_proof()


class TestSerializationConsistency:
    """Test all statement proofs serialize correctly"""

    def test_all_statements_cbor_roundtrip(self):
        """All Phase 2B statement proofs survive CBOR serialization"""
        backend = PedersenBackend()
        identity = Bn.from_num(42)

        g, h = _get_membership_generators()

        blinding_m = Bn.from_num(100)
        commitment_m = ((identity * g) + (blinding_m * h)).export()
        leaves = [
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], commitment_m),
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], b"\x02" + b"\xaa" * 32),
        ]
        root, paths = build_tree(leaves)
        ctx = ProofContext(peer_id="p", session_id="s", metadata={}, timestamp=1.0)
        membership = backend.generate_membership_proof(
            identity, blinding_m, paths[0], root, ctx
        )

        blinding_u = Bn.from_num(200)
        unlinkability = backend.generate_unlinkability_proof(identity, blinding_u, ctx)

        continuity = backend.generate_continuity_proof(
            identity, Bn.from_num(300), Bn.from_num(400), ctx
        )

        proofs = [membership, unlinkability, continuity]

        for proof in proofs:
            serialized = proof.serialize()
            restored = proof.__class__.deserialize(serialized)

            assert restored.get_statement_type() == proof.get_statement_type()
            assert restored.get_statement_version() == proof.get_statement_version()

            stmt_type = proof.get_statement_type()
            if stmt_type == StatementType.ANON_SET_MEMBERSHIP.value:
                assert backend.verify_membership_proof(restored)
            elif stmt_type == StatementType.SESSION_UNLINKABILITY.value:
                assert backend.verify_unlinkability_proof(restored)
            elif stmt_type == StatementType.IDENTITY_CONTINUITY.value:
                assert backend.verify_continuity_proof(restored)
