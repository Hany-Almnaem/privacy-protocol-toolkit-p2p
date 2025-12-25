import pytest

from libp2p_privacy_poc.privacy_protocol import statements


def _base_public_inputs(statement_type: statements.StatementType) -> dict:
    if statement_type == statements.StatementType.ANON_SET_MEMBERSHIP:
        return {
            "statement_type": statement_type.value,
            "statement_version": 1,
            "root": b"\x00" * 32,
            "commitment": b"\x01" * 33,
            "ctx_hash": b"\x02" * 32,
            "domain_sep": b"DOMAIN",
        }
    if statement_type == statements.StatementType.SESSION_UNLINKABILITY:
        return {
            "statement_type": statement_type.value,
            "statement_version": 1,
            "tag": b"\x03" * 32,
            "commitment": b"\x01" * 33,
            "ctx_hash": b"\x02" * 32,
            "domain_sep": b"DOMAIN",
        }
    if statement_type == statements.StatementType.IDENTITY_CONTINUITY:
        return {
            "statement_type": statement_type.value,
            "statement_version": 1,
            "commitment_1": b"\x01" * 33,
            "commitment_2": b"\x04" * 33,
            "ctx_hash": b"\x02" * 32,
            "domain_sep": b"DOMAIN",
        }
    raise ValueError("unsupported statement_type")


def test_registry_contains_phase2b_types():
    assert statements.StatementType.ANON_SET_MEMBERSHIP in statements.STATEMENT_REGISTRY
    assert statements.StatementType.SESSION_UNLINKABILITY in statements.STATEMENT_REGISTRY
    assert statements.StatementType.IDENTITY_CONTINUITY in statements.STATEMENT_REGISTRY


def test_get_statement_spec_unknown_raises():
    with pytest.raises(ValueError, match="Unknown statement type"):
        statements.get_statement_spec("not-a-type")  # type: ignore[arg-type]


def test_validate_public_inputs_success_for_each_statement():
    for statement_type in [
        statements.StatementType.ANON_SET_MEMBERSHIP,
        statements.StatementType.SESSION_UNLINKABILITY,
        statements.StatementType.IDENTITY_CONTINUITY,
    ]:
        public_inputs = _base_public_inputs(statement_type)
        statements.validate_public_inputs(statement_type, public_inputs)


def test_validate_public_inputs_missing_field():
    public_inputs = _base_public_inputs(statements.StatementType.ANON_SET_MEMBERSHIP)
    public_inputs.pop("root")
    with pytest.raises(ValueError, match="Missing required field 'root'"):
        statements.validate_public_inputs(
            statements.StatementType.ANON_SET_MEMBERSHIP, public_inputs
        )


def test_validate_public_inputs_type_mismatch():
    public_inputs = _base_public_inputs(statements.StatementType.SESSION_UNLINKABILITY)
    public_inputs["tag"] = "not-bytes"
    with pytest.raises(ValueError, match="Field 'tag' must be bytes"):
        statements.validate_public_inputs(
            statements.StatementType.SESSION_UNLINKABILITY, public_inputs
        )


def test_validate_public_inputs_version_mismatch():
    public_inputs = _base_public_inputs(statements.StatementType.IDENTITY_CONTINUITY)
    public_inputs["statement_version"] = 2
    with pytest.raises(ValueError, match="Statement version mismatch"):
        statements.validate_public_inputs(
            statements.StatementType.IDENTITY_CONTINUITY, public_inputs
        )
