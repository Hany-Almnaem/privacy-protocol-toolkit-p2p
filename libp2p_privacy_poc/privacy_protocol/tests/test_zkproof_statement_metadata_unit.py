import pytest

from ..types import ZKProof


def test_helpers_without_statement_metadata():
    proof = ZKProof(proof_type="anonymity_set_membership", commitment=b"\x01")

    assert proof.get_statement_type() is None
    assert proof.get_statement_version() is None
    assert proof.is_phase2b_proof() is False

    proof.validate_statement_metadata()


def test_helpers_with_statement_metadata():
    proof = ZKProof(
        proof_type="anonymity_set_membership",
        commitment=b"\x01",
        public_inputs={
            "statement_type": "anon_set_membership_v1",
            "statement_version": 1,
        },
    )

    assert proof.get_statement_type() == "anon_set_membership_v1"
    assert proof.get_statement_version() == 1
    assert proof.is_phase2b_proof() is True


def test_validate_statement_metadata_invalid_type():
    proof = ZKProof(
        proof_type="anonymity_set_membership",
        commitment=b"\x01",
        public_inputs={"statement_type": "not-a-type", "statement_version": 1},
    )

    with pytest.raises(ValueError, match="Invalid statement type"):
        proof.validate_statement_metadata()
