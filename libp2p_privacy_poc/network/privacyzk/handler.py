"""Pure request/response handler for proof exchange."""

from __future__ import annotations

from typing import Optional

import cbor2

from .constants import DEFAULT_MEMBERSHIP_DEPTH, MSG_V, SNARK_SCHEMA_V
from .errors import ProtocolError, SchemaError, SizeLimitError
from .messages import ProofRequest, ProofResponse, decode_request, encode_response
from .provider import ProofProvider, _encode_meta


def _error_response(
    err: str,
    statement_type: str = "membership",
    schema_v: int = SNARK_SCHEMA_V,
    depth: int = DEFAULT_MEMBERSHIP_DEPTH,
    prove_mode: str = "fixture",
) -> ProofResponse:
    meta = {
        "prove_mode": prove_mode,
        "statement": statement_type,
        "schema_v": schema_v,
        "depth": depth,
    }
    return ProofResponse(
        msg_v=MSG_V,
        ok=False,
        t=statement_type,
        schema_v=schema_v,
        d=depth,
        public_inputs=b"",
        proof=b"",
        meta=_encode_meta(meta),
        err=err,
    )


def handle_proof_request_bytes(
    request_blob: bytes, provider: ProofProvider
) -> bytes:
    try:
        req = decode_request(request_blob)
    except (SchemaError, SizeLimitError) as exc:
        resp = _error_response(f"bad request: {exc}")
        try:
            return encode_response(resp)
        except ProtocolError:
            minimal = _error_response("bad request")
            return encode_response(minimal)
    except Exception:
        resp = _error_response("bad request: decode failed")
        return encode_response(resp)

    try:
        response = provider.get_proof(req)
    except Exception:
        response = _error_response("provider error", req.t, req.schema_v, req.d)

    try:
        return encode_response(response)
    except SizeLimitError:
        resp = _error_response("response too large", req.t, req.schema_v, req.d)
        return encode_response(resp)
