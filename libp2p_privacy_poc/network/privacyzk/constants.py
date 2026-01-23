"""Protocol constants for privacy proof exchange."""

from __future__ import annotations

PROTOCOL_ID = "/privacyzk/1.0.0"
MSG_V = 1
STATEMENT_TYPES = frozenset({"membership", "continuity", "unlinkability"})
SNARK_SCHEMA_V = 2
DEFAULT_MEMBERSHIP_DEPTH = 16

MAX_PROOF_BYTES = 4096
MAX_PUBLIC_INPUTS_BYTES = 65536
MAX_META_BYTES = 4096


def is_valid_statement_type(statement_type: str) -> bool:
    return statement_type in STATEMENT_TYPES
