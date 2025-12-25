"""
Statement registry for Phase 2B privacy statements.
Defines statement types, versions, and validation schemas.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional


class StatementType(Enum):
    """Statement types for privacy proofs"""

    # Phase 2A (existing, for backward compatibility)
    COMMITMENT_OPENING = "commitment_opening_v1"

    # Phase 2B (new)
    ANON_SET_MEMBERSHIP = "anon_set_membership_v1"
    SESSION_UNLINKABILITY = "session_unlinkability_v1"
    IDENTITY_CONTINUITY = "identity_continuity_v1"


@dataclass
class StatementSpec:
    """
    Specification for a privacy statement.

    Attributes:
        statement_type: Type identifier
        version: Statement version (for future upgrades)
        public_input_schema: Required fields in public_inputs
        witness_schema: Required witness components (for documentation)
        description: Human-readable statement description
    """

    statement_type: StatementType
    version: int
    public_input_schema: Dict[str, type]
    witness_schema: Dict[str, type]
    description: str


# Registry of all supported statements
STATEMENT_REGISTRY: Dict[StatementType, StatementSpec] = {
    StatementType.ANON_SET_MEMBERSHIP: StatementSpec(
        statement_type=StatementType.ANON_SET_MEMBERSHIP,
        version=1,
        public_input_schema={
            "statement_type": str,
            "statement_version": int,
            "root": bytes,  # Merkle root
            "commitment": bytes,  # Commitment being proven
            "ctx_hash": bytes,
            "domain_sep": bytes,
        },
        witness_schema={
            "identity_scalar": "Bn",
            "blinding": "Bn",
            "merkle_path": "List[Tuple[bytes, bool]]",
        },
        description="Prove commitment is in Merkle tree anonymity set",
    ),
    StatementType.SESSION_UNLINKABILITY: StatementSpec(
        statement_type=StatementType.SESSION_UNLINKABILITY,
        version=1,
        public_input_schema={
            "statement_type": str,
            "statement_version": int,
            "tag": bytes,  # Session identifier
            "commitment": bytes,
            "ctx_hash": bytes,
            "domain_sep": bytes,
        },
        witness_schema={
            "identity_scalar": "Bn",
            "blinding": "Bn",
        },
        description="Prove session tag unlinkability across contexts",
    ),
    StatementType.IDENTITY_CONTINUITY: StatementSpec(
        statement_type=StatementType.IDENTITY_CONTINUITY,
        version=1,
        public_input_schema={
            "statement_type": str,
            "statement_version": int,
            "commitment_1": bytes,
            "commitment_2": bytes,
            "ctx_hash": bytes,
            "domain_sep": bytes,
        },
        witness_schema={
            "identity_scalar": "Bn",
            "blinding_1": "Bn",
            "blinding_2": "Bn",
        },
        description="Prove same identity across two commitments",
    ),
}


def validate_public_inputs(
    statement_type: StatementType, public_inputs: Dict[str, Any]
) -> None:
    """
    Validate public inputs match statement schema.

    Raises:
        ValueError: If inputs don't match schema
    """
    if statement_type not in STATEMENT_REGISTRY:
        raise ValueError(f"Unknown statement type: {statement_type}")

    spec = STATEMENT_REGISTRY[statement_type]
    schema = spec.public_input_schema

    # Check all required fields present
    for field, expected_type in schema.items():
        if field not in public_inputs:
            raise ValueError(
                f"Missing required field '{field}' for {statement_type.value}"
            )

        actual_value = public_inputs[field]

        # Type checking (basic)
        if expected_type == bytes and not isinstance(actual_value, bytes):
            raise ValueError(
                f"Field '{field}' must be bytes, got {type(actual_value)}"
            )
        elif expected_type == str and not isinstance(actual_value, str):
            raise ValueError(
                f"Field '{field}' must be str, got {type(actual_value)}"
            )
        elif expected_type == int and not isinstance(actual_value, int):
            raise ValueError(
                f"Field '{field}' must be int, got {type(actual_value)}"
            )

    # Check version matches
    if public_inputs["statement_version"] != spec.version:
        raise ValueError(
            f"Statement version mismatch: expected {spec.version}, "
            f"got {public_inputs['statement_version']}"
        )


def get_statement_spec(statement_type: StatementType) -> StatementSpec:
    """Get specification for a statement type"""
    if statement_type not in STATEMENT_REGISTRY:
        raise ValueError(f"Unknown statement type: {statement_type}")
    return STATEMENT_REGISTRY[statement_type]
