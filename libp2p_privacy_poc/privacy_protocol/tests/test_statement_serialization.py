"""Test CBOR serialization for Phase 2B statement proofs"""

import cbor2
import pytest
from privacy_protocol.types import ZKProof, ZKProofType


def test_phase2b_proof_cbor_roundtrip():
    """Phase 2B proof survives CBOR serialization"""
    original_proof = ZKProof(
        proof_type=ZKProofType.PEDERSEN_OPENING,
        commitment=b"\x02" + b"\xab" * 32,
        challenge=b"\xcd" * 32,
        response=b"\xef" * 32,
        public_inputs={
            "statement_type": "anon_set_membership_v1",
            "statement_version": 1,
            "root": b"\x12" * 32,
            "commitment": b"\x02" + b"\x34" * 32,
            "ctx_hash": b"\x56" * 32,
            "domain_sep": b"MEMBERSHIP_TEST",
        },
        timestamp=1234567890.0,
    )

    # Serialize
    serialized = original_proof.serialize()
    assert isinstance(serialized, bytes)

    # Deserialize
    restored_proof = ZKProof.deserialize(serialized)

    # Verify all fields match
    assert restored_proof.proof_type == original_proof.proof_type
    assert restored_proof.commitment == original_proof.commitment
    assert restored_proof.challenge == original_proof.challenge
    assert restored_proof.response == original_proof.response
    assert restored_proof.timestamp == original_proof.timestamp

    # Verify public_inputs match exactly
    assert restored_proof.public_inputs == original_proof.public_inputs

    # Verify statement metadata preserved
    assert restored_proof.get_statement_type() == "anon_set_membership_v1"
    assert restored_proof.get_statement_version() == 1

    # Validation should pass
    restored_proof.validate_statement_metadata()


def test_merkle_path_serialization():
    """Merkle path structure survives CBOR"""
    merkle_path = [
        {"sibling": b"\xaa" * 32, "is_left": True},
        {"sibling": b"\xbb" * 32, "is_left": False},
        {"sibling": b"\xcc" * 32, "is_left": True},
    ]

    public_inputs = {
        "statement_type": "anon_set_membership_v1",
        "statement_version": 1,
        "root": b"\x00" * 32,
        "commitment": b"\x02" + b"\x00" * 32,
        "ctx_hash": b"\x00" * 32,
        "domain_sep": b"TEST",
        "merkle_path": merkle_path,  # Nested structure
    }

    # CBOR round-trip
    encoded = cbor2.dumps(public_inputs)
    decoded = cbor2.loads(encoded)

    # Verify path structure preserved
    assert decoded["merkle_path"] == merkle_path
    assert len(decoded["merkle_path"]) == 3
    assert decoded["merkle_path"][0]["is_left"] is True
    assert decoded["merkle_path"][1]["is_left"] is False
