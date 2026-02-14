"""Unit tests for privacy proof message schemas."""

from __future__ import annotations

import pytest

from libp2p_privacy_poc.network.privacyzk.constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MAX_META_BYTES,
    MAX_PROOF_BYTES,
    MAX_PUBLIC_INPUTS_BYTES,
    MSG_V,
    SNARK_SCHEMA_V,
)
from libp2p_privacy_poc.network.privacyzk.errors import SchemaError, SizeLimitError
from libp2p_privacy_poc.network.privacyzk.messages import (
    ProofRequest,
    ProofResponse,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)


def _nonce(length: int = 16) -> bytes:
    return b"n" * length


def test_request_roundtrip_valid_membership() -> None:
    req = ProofRequest(
        msg_v=MSG_V,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=_nonce(),
    )
    blob = encode_request(req)
    decoded = decode_request(blob)
    assert decoded == req


def test_request_roundtrip_valid_continuity_depth0() -> None:
    req = ProofRequest(
        msg_v=MSG_V,
        t="continuity",
        schema_v=SNARK_SCHEMA_V,
        d=0,
        nonce=_nonce(32),
    )
    decoded = decode_request(encode_request(req))
    assert decoded == req


def test_request_rejects_bad_msg_v() -> None:
    req = ProofRequest(
        msg_v=MSG_V + 1,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=_nonce(),
    )
    with pytest.raises(SchemaError, match="msg_v"):
        encode_request(req)


def test_request_rejects_bad_statement_type() -> None:
    req = ProofRequest(
        msg_v=MSG_V,
        t="bad",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=_nonce(),
    )
    with pytest.raises(SchemaError, match="statement type"):
        encode_request(req)


def test_request_rejects_bad_schema_v() -> None:
    req = ProofRequest(
        msg_v=MSG_V,
        t="membership",
        schema_v=SNARK_SCHEMA_V - 1,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=_nonce(),
    )
    with pytest.raises(SchemaError, match="schema_v"):
        encode_request(req)


def test_request_rejects_bad_depth_rules() -> None:
    bad_membership = ProofRequest(
        msg_v=MSG_V,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=0,
        nonce=_nonce(),
    )
    with pytest.raises(SchemaError, match="membership depth"):
        encode_request(bad_membership)

    bad_continuity = ProofRequest(
        msg_v=MSG_V,
        t="continuity",
        schema_v=SNARK_SCHEMA_V,
        d=1,
        nonce=_nonce(),
    )
    with pytest.raises(SchemaError, match="non-membership depth"):
        encode_request(bad_continuity)


def test_request_rejects_nonce_size() -> None:
    too_short = ProofRequest(
        msg_v=MSG_V,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=_nonce(15),
    )
    with pytest.raises(SchemaError, match="nonce length"):
        encode_request(too_short)

    too_long = ProofRequest(
        msg_v=MSG_V,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        nonce=_nonce(65),
    )
    with pytest.raises(SchemaError, match="nonce length"):
        encode_request(too_long)


def test_response_roundtrip_ok_true() -> None:
    resp = ProofResponse(
        msg_v=MSG_V,
        ok=True,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        public_inputs=b"pi",
        proof=b"proof",
        meta={  # type: ignore[arg-type]
            "prove_mode": "fixture",
            "statement": "membership",
        },
        err=None,
    )
    decoded = decode_response(encode_response(resp))
    assert decoded.ok is True
    assert decoded.public_inputs == b"pi"
    assert decoded.proof == b"proof"
    assert isinstance(decoded.meta, bytes)
    assert decoded.meta


def test_response_roundtrip_ok_false() -> None:
    resp = ProofResponse(
        msg_v=MSG_V,
        ok=False,
        t="continuity",
        schema_v=SNARK_SCHEMA_V,
        d=0,
        public_inputs=b"",
        proof=b"",
        meta=b"",
        err="bad request",
    )
    decoded = decode_response(encode_response(resp))
    assert decoded.ok is False
    assert decoded.public_inputs == b""
    assert decoded.proof == b""
    assert decoded.err == "bad request"


def test_response_rejects_oversized_proof() -> None:
    resp = ProofResponse(
        msg_v=MSG_V,
        ok=True,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        public_inputs=b"pi",
        proof=b"p" * (MAX_PROOF_BYTES + 1),
        meta=b"",
        err=None,
    )
    with pytest.raises(SizeLimitError, match="proof too large"):
        encode_response(resp)


def test_response_rejects_oversized_public_inputs() -> None:
    resp = ProofResponse(
        msg_v=MSG_V,
        ok=True,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        public_inputs=b"p" * (MAX_PUBLIC_INPUTS_BYTES + 1),
        proof=b"proof",
        meta=b"",
        err=None,
    )
    with pytest.raises(SizeLimitError, match="public_inputs too large"):
        encode_response(resp)


def test_response_rejects_oversized_meta() -> None:
    resp = ProofResponse(
        msg_v=MSG_V,
        ok=True,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        public_inputs=b"pi",
        proof=b"proof",
        meta=b"m" * (MAX_META_BYTES + 1),
        err=None,
    )
    with pytest.raises(SizeLimitError, match="meta too large"):
        encode_response(resp)


def test_response_rejects_err_too_long() -> None:
    resp = ProofResponse(
        msg_v=MSG_V,
        ok=False,
        t="continuity",
        schema_v=SNARK_SCHEMA_V,
        d=0,
        public_inputs=b"",
        proof=b"",
        meta=b"",
        err="e" * 257,
    )
    with pytest.raises(SchemaError, match="err too long"):
        encode_response(resp)


def test_meta_dict_is_encoded_to_bytes_and_limited() -> None:
    meta = {"prove_mode": "fixture"}
    resp = ProofResponse(
        msg_v=MSG_V,
        ok=True,
        t="continuity",
        schema_v=SNARK_SCHEMA_V,
        d=0,
        public_inputs=b"pi",
        proof=b"proof",
        meta=meta,  # type: ignore[arg-type]
        err=None,
    )
    decoded = decode_response(encode_response(resp))
    assert isinstance(decoded.meta, bytes)
    assert decoded.meta
