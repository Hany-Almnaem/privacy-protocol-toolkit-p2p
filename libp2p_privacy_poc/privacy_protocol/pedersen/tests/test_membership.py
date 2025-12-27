"""Tests for anonymity set membership proofs"""

import pytest
from petlib.ec import EcGroup
from petlib.bn import Bn

try:
    from privacy_protocol.pedersen.membership import (
        generate_membership_proof,
        verify_membership_proof,
        g, h, order
    )
    from privacy_protocol.merkle import hash_leaf, build_tree, DOMAIN_SEPARATORS_2B
    from privacy_protocol.types import ProofContext
except ModuleNotFoundError:
    from ..membership import (
        generate_membership_proof,
        verify_membership_proof,
        g, h, order
    )
    from ...merkle import hash_leaf, build_tree, DOMAIN_SEPARATORS_2B
    from ...types import ProofContext


def _build_anonymity_set(count: int = 4):
    identities = [Bn.from_num(i + 1) for i in range(count)]
    blindings = [Bn.from_num(i + 100) for i in range(count)]

    commitments = [
        ((id_scalar * g) + (blind * h)).export()
        for id_scalar, blind in zip(identities, blindings)
    ]

    leaves = [
        hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], c)
        for c in commitments
    ]
    root, paths = build_tree(leaves)
    return identities, blindings, commitments, root, paths


class TestMembershipProof:
    """Test membership proof generation and verification"""

    def test_valid_membership_proof_verifies(self):
        """Valid membership proof passes verification"""
        identities, blindings, _, root, paths = _build_anonymity_set()

        my_index = 0
        my_id = identities[my_index]
        my_blind = blindings[my_index]
        my_path = paths[my_index]

        ctx = ProofContext(
            peer_id="test_peer",
            session_id="test_session",
            metadata={},
            timestamp=0.0
        )
        ctx_hash = ctx.to_bytes()

        proof = generate_membership_proof(
            identity_scalar=my_id,
            blinding=my_blind,
            merkle_path=my_path,
            root=root,
            ctx_hash=ctx_hash
        )

        assert verify_membership_proof(proof)

    def test_wrong_root_fails(self):
        """Proof with wrong root fails"""
        identities, blindings, _, root, paths = _build_anonymity_set()

        my_index = 0
        my_id = identities[my_index]
        my_blind = blindings[my_index]
        my_path = paths[my_index]

        ctx_hash = b"\x00" * 32
        proof = generate_membership_proof(
            identity_scalar=my_id,
            blinding=my_blind,
            merkle_path=my_path,
            root=root,
            ctx_hash=ctx_hash
        )

        proof.public_inputs["root"] = b"\xff" * 32
        assert not verify_membership_proof(proof)

    def test_tampered_path_fails(self):
        """Tampered Merkle path fails"""
        identities, blindings, _, root, paths = _build_anonymity_set()

        my_index = 1
        my_id = identities[my_index]
        my_blind = blindings[my_index]
        my_path = paths[my_index]

        ctx_hash = b"\x11" * 32
        proof = generate_membership_proof(
            identity_scalar=my_id,
            blinding=my_blind,
            merkle_path=my_path,
            root=root,
            ctx_hash=ctx_hash
        )

        proof.public_inputs["merkle_path"][0]["sibling"] = b"\xaa" * 32
        assert not verify_membership_proof(proof)

    def test_tampered_commitment_fails(self):
        """Tampered commitment fails"""
        identities, blindings, _, root, paths = _build_anonymity_set()

        my_index = 2
        my_id = identities[my_index]
        my_blind = blindings[my_index]
        my_path = paths[my_index]

        ctx_hash = b"\x22" * 32
        proof = generate_membership_proof(
            identity_scalar=my_id,
            blinding=my_blind,
            merkle_path=my_path,
            root=root,
            ctx_hash=ctx_hash
        )

        proof.public_inputs["commitment"] = b"\x02" + b"\x00" * 32
        assert not verify_membership_proof(proof)

    def test_wrong_identity_fails(self):
        """Proof with wrong identity scalar fails"""
        identities, blindings, _, root, paths = _build_anonymity_set()

        my_index = 0
        my_path = paths[my_index]
        ctx_hash = b"\x33" * 32

        wrong_identity = identities[1]
        wrong_blinding = blindings[1]

        with pytest.raises(ValueError, match="Merkle path verification failed"):
            generate_membership_proof(
                identity_scalar=wrong_identity,
                blinding=wrong_blinding,
                merkle_path=my_path,
                root=root,
                ctx_hash=ctx_hash
            )
