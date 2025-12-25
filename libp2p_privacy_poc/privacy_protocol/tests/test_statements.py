"""Tests for statement registry and validation"""

import pytest
from privacy_protocol.statements import (
    StatementType,
    StatementSpec,
    STATEMENT_REGISTRY,
    validate_public_inputs,
    get_statement_spec,
)


class TestStatementRegistry:
    """Test statement registry definitions"""

    def test_all_statements_registered(self):
        """All Phase 2B statements are in registry"""
        expected_types = [
            StatementType.ANON_SET_MEMBERSHIP,
            StatementType.SESSION_UNLINKABILITY,
            StatementType.IDENTITY_CONTINUITY,
        ]
        for stmt_type in expected_types:
            assert stmt_type in STATEMENT_REGISTRY

    def test_statement_spec_structure(self):
        """Each spec has required fields"""
        for stmt_type, spec in STATEMENT_REGISTRY.items():
            assert spec.statement_type == stmt_type
            assert spec.version > 0
            assert isinstance(spec.public_input_schema, dict)
            assert isinstance(spec.witness_schema, dict)
            assert len(spec.description) > 0

    def test_public_input_schemas_have_common_fields(self):
        """All statements require standard metadata fields"""
        required_common = {
            "statement_type", "statement_version", "ctx_hash", "domain_sep"
        }
        for spec in STATEMENT_REGISTRY.values():
            schema_fields = set(spec.public_input_schema.keys())
            assert required_common.issubset(schema_fields), \
                f"{spec.statement_type} missing common fields"


class TestPublicInputValidation:
    """Test public input validation"""

    def test_valid_membership_inputs(self):
        """Valid membership public inputs pass validation"""
        public_inputs = {
            "statement_type": "anon_set_membership_v1",
            "statement_version": 1,
            "root": b"\x00" * 32,
            "commitment": b"\x02" + b"\x00" * 32,
            "ctx_hash": b"\x00" * 32,
            "domain_sep": b"TEST",
        }
        # Should not raise
        validate_public_inputs(
            StatementType.ANON_SET_MEMBERSHIP, public_inputs
        )

    def test_missing_required_field_fails(self):
        """Missing required field raises ValueError"""
        public_inputs = {
            "statement_type": "anon_set_membership_v1",
            "statement_version": 1,
            # Missing "root"
            "commitment": b"\x02" + b"\x00" * 32,
            "ctx_hash": b"\x00" * 32,
            "domain_sep": b"TEST",
        }
        with pytest.raises(ValueError, match="Missing required field 'root'"):
            validate_public_inputs(
                StatementType.ANON_SET_MEMBERSHIP, public_inputs
            )

    def test_wrong_field_type_fails(self):
        """Wrong field type raises ValueError"""
        public_inputs = {
            "statement_type": "anon_set_membership_v1",
            "statement_version": 1,
            "root": "not_bytes",  # Should be bytes
            "commitment": b"\x02" + b"\x00" * 32,
            "ctx_hash": b"\x00" * 32,
            "domain_sep": b"TEST",
        }
        with pytest.raises(ValueError, match="must be bytes"):
            validate_public_inputs(
                StatementType.ANON_SET_MEMBERSHIP, public_inputs
            )

    def test_version_mismatch_fails(self):
        """Version mismatch raises ValueError"""
        public_inputs = {
            "statement_type": "anon_set_membership_v1",
            "statement_version": 999,  # Wrong version
            "root": b"\x00" * 32,
            "commitment": b"\x02" + b"\x00" * 32,
            "ctx_hash": b"\x00" * 32,
            "domain_sep": b"TEST",
        }
        with pytest.raises(ValueError, match="version mismatch"):
            validate_public_inputs(
                StatementType.ANON_SET_MEMBERSHIP, public_inputs
            )


class TestZKProofIntegration:
    """Test ZKProof helper methods"""

    def test_phase2a_proof_not_statement_proof(self):
        """Phase 2A proof returns None for statement type"""
        from privacy_protocol.types import ZKProof, ZKProofType

        proof = ZKProof(
            proof_type=ZKProofType.PEDERSEN_OPENING,
            commitment=b"\x00" * 33,
            challenge=b"\x00" * 32,
            response=b"\x00" * 32,
            public_inputs={},  # No statement metadata
            timestamp=0.0,
        )
        assert proof.get_statement_type() is None
        assert not proof.is_phase2b_proof()

    def test_phase2b_proof_has_statement_type(self):
        """Phase 2B proof returns statement type"""
        from privacy_protocol.types import ZKProof, ZKProofType

        proof = ZKProof(
            proof_type=ZKProofType.PEDERSEN_OPENING,
            commitment=b"\x00" * 33,
            challenge=b"\x00" * 32,
            response=b"\x00" * 32,
            public_inputs={
                "statement_type": "anon_set_membership_v1",
                "statement_version": 1,
                "root": b"\x00" * 32,
                "commitment": b"\x02" + b"\x00" * 32,
                "ctx_hash": b"\x00" * 32,
                "domain_sep": b"TEST",
            },
            timestamp=0.0,
        )
        assert proof.get_statement_type() == "anon_set_membership_v1"
        assert proof.get_statement_version() == 1
        assert proof.is_phase2b_proof()

    def test_validate_statement_metadata_passes_for_phase2a(self):
        """Validation passes for Phase 2A proofs"""
        from privacy_protocol.types import ZKProof, ZKProofType

        proof = ZKProof(
            proof_type=ZKProofType.PEDERSEN_OPENING,
            commitment=b"\x00" * 33,
            challenge=b"\x00" * 32,
            response=b"\x00" * 32,
            public_inputs={},
            timestamp=0.0,
        )
        # Should not raise
        proof.validate_statement_metadata()
