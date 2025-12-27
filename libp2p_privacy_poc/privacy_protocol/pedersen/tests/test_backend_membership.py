import hashlib

from petlib.bn import Bn

from ..backend import PedersenBackend
from .. import membership
from ...merkle import hash_leaf, build_tree, DOMAIN_SEPARATORS_2B
from ...types import ProofContext


def _build_membership_inputs():
    identity_scalar = Bn.from_num(1)
    blinding = Bn.from_num(100)

    commitment_point = (identity_scalar * membership.g) + (blinding * membership.h)
    commitment_bytes = commitment_point.export()
    leaf_hash = hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], commitment_bytes)

    other_leaf_1 = hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], b"other_leaf_1")
    other_leaf_2 = hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], b"other_leaf_2")

    leaves = [leaf_hash, other_leaf_1, other_leaf_2]
    root, paths = build_tree(leaves)

    ctx = ProofContext(
        peer_id="backend_peer",
        session_id="backend_session",
        metadata={},
        timestamp=0.0,
    )

    return identity_scalar, blinding, root, paths[0], ctx


def test_backend_generate_and_verify_membership_proof():
    identity_scalar, blinding, root, path, ctx = _build_membership_inputs()

    backend = PedersenBackend()
    proof = backend.generate_membership_proof(
        identity_scalar=identity_scalar,
        blinding=blinding,
        merkle_path=path,
        root=root,
        context=ctx,
    )

    expected_ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()
    assert proof.public_inputs["ctx_hash"] == expected_ctx_hash
    assert backend.verify_membership_proof(proof) is True


def test_backend_verify_membership_proof_rejects_tampered_root():
    identity_scalar, blinding, root, path, ctx = _build_membership_inputs()

    backend = PedersenBackend()
    proof = backend.generate_membership_proof(
        identity_scalar=identity_scalar,
        blinding=blinding,
        merkle_path=path,
        root=root,
        context=ctx,
    )

    proof.public_inputs["root"] = b"\xff" * 32
    assert backend.verify_membership_proof(proof) is False
