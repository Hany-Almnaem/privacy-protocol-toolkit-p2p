import pytest

from ..statements import StatementType
from ..types import ZKProof


def _public_inputs_for(statement_type: StatementType) -> dict:
    if statement_type == StatementType.ANON_SET_MEMBERSHIP:
        return {
            "statement_type": statement_type.value,
            "statement_version": 1,
            "root": b"\x00" * 32,
            "commitment": b"\x01" * 33,
            "ctx_hash": b"\x02" * 32,
            "domain_sep": b"DOMAIN",
        }
    if statement_type == StatementType.SESSION_UNLINKABILITY:
        return {
            "statement_type": statement_type.value,
            "statement_version": 1,
            "tag": b"\x03" * 32,
            "commitment": b"\x01" * 33,
            "ctx_hash": b"\x02" * 32,
            "domain_sep": b"DOMAIN",
        }
    if statement_type == StatementType.IDENTITY_CONTINUITY:
        return {
            "statement_type": statement_type.value,
            "statement_version": 1,
            "commitment_1": b"\x01" * 33,
            "commitment_2": b"\x04" * 33,
            "ctx_hash": b"\x02" * 32,
            "domain_sep": b"DOMAIN",
        }
    raise ValueError("unsupported statement_type")


def test_validate_statement_metadata_for_each_statement():
    for statement_type in [
        StatementType.ANON_SET_MEMBERSHIP,
        StatementType.SESSION_UNLINKABILITY,
        StatementType.IDENTITY_CONTINUITY,
    ]:
        proof = ZKProof(
            proof_type="anonymity_set_membership",
            commitment=b"\x01",
            public_inputs=_public_inputs_for(statement_type),
        )

        proof.validate_statement_metadata()


def test_validate_statement_metadata_missing_required_field():
    public_inputs = _public_inputs_for(StatementType.ANON_SET_MEMBERSHIP)
    public_inputs.pop("root")
    proof = ZKProof(
        proof_type="anonymity_set_membership",
        commitment=b"\x01",
        public_inputs=public_inputs,
    )

    with pytest.raises(ValueError, match="Missing required field 'root'"):
        proof.validate_statement_metadata()
