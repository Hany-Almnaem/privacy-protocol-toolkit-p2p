"""CBOR message schemas for privacy proof exchange."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

import cbor2

from .constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MAX_META_BYTES,
    MAX_PROOF_BYTES,
    MAX_PUBLIC_INPUTS_BYTES,
    MSG_V,
    SNARK_SCHEMA_V,
    STATEMENT_TYPES,
)
from .errors import SchemaError, SizeLimitError

REQUEST_MAX_BYTES = 8192
RESPONSE_OVERHEAD_BYTES = 2048
RESPONSE_MAX_BYTES = (
    MAX_PUBLIC_INPUTS_BYTES + MAX_PROOF_BYTES + MAX_META_BYTES + RESPONSE_OVERHEAD_BYTES
)


def _require_bytes(value: Any, field: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise SchemaError(f"{field} must be bytes")
    return bytes(value)


def _validate_statement_depth(statement_type: str, depth: int) -> None:
    if statement_type == "membership":
        if depth < 1:
            raise SchemaError("membership depth must be >= 1")
    else:
        if depth != 0:
            raise SchemaError("non-membership depth must be 0")


@dataclass(frozen=True)
class ProofRequest:
    msg_v: int
    t: str
    schema_v: int
    d: int
    nonce: bytes

    def validate(self) -> None:
        if self.msg_v != MSG_V:
            raise SchemaError("unsupported msg_v")
        if self.t not in STATEMENT_TYPES:
            raise SchemaError("unsupported statement type")
        if self.schema_v != SNARK_SCHEMA_V:
            raise SchemaError("unsupported schema_v")
        _validate_statement_depth(self.t, self.d)
        if not isinstance(self.nonce, (bytes, bytearray)):
            raise SchemaError("nonce must be bytes")
        nonce_len = len(self.nonce)
        if nonce_len < 16 or nonce_len > 64:
            raise SchemaError("nonce length out of bounds")


@dataclass(frozen=True)
class ProofResponse:
    msg_v: int
    ok: bool
    t: str
    schema_v: int
    d: int
    public_inputs: bytes
    proof: bytes
    meta: bytes
    err: Optional[str]

    def validate(self) -> None:
        if self.msg_v != MSG_V:
            raise SchemaError("unsupported msg_v")
        if self.t not in STATEMENT_TYPES:
            raise SchemaError("unsupported statement type")
        if self.schema_v != SNARK_SCHEMA_V:
            raise SchemaError("unsupported schema_v")
        _validate_statement_depth(self.t, self.d)

        public_inputs = _require_bytes(self.public_inputs, "public_inputs")
        proof = _require_bytes(self.proof, "proof")
        meta = _require_bytes(self.meta, "meta")

        if len(public_inputs) > MAX_PUBLIC_INPUTS_BYTES:
            raise SizeLimitError("public_inputs too large")
        if len(proof) > MAX_PROOF_BYTES:
            raise SizeLimitError("proof too large")
        if len(meta) > MAX_META_BYTES:
            raise SizeLimitError("meta too large")

        if self.ok:
            if not public_inputs:
                raise SchemaError("public_inputs required when ok=True")
            if not proof:
                raise SchemaError("proof required when ok=True")
            if self.err not in (None, ""):
                raise SchemaError("err must be empty when ok=True")
        else:
            if public_inputs or proof:
                raise SchemaError("public_inputs/proof must be empty when ok=False")
            if not isinstance(self.err, str) or not self.err:
                raise SchemaError("err required when ok=False")
            if len(self.err) > 256:
                raise SchemaError("err too long")


def encode_request(req: ProofRequest) -> bytes:
    req.validate()
    payload = {
        "msg_v": req.msg_v,
        "t": req.t,
        "schema_v": req.schema_v,
        "d": req.d,
        "nonce": bytes(req.nonce),
    }
    blob = cbor2.dumps(payload)
    if len(blob) > REQUEST_MAX_BYTES:
        raise SizeLimitError("request too large")
    return blob


def decode_request(blob: bytes) -> ProofRequest:
    if not isinstance(blob, (bytes, bytearray)):
        raise SchemaError("request blob must be bytes")
    blob_bytes = bytes(blob)
    if len(blob_bytes) > REQUEST_MAX_BYTES:
        raise SizeLimitError("request too large")
    payload = cbor2.loads(blob_bytes)
    if not isinstance(payload, dict):
        raise SchemaError("request payload must be a dict")
    req = ProofRequest(
        msg_v=int(payload.get("msg_v", -1)),
        t=payload.get("t", ""),
        schema_v=int(payload.get("schema_v", -1)),
        d=int(payload.get("d", -1)),
        nonce=_require_bytes(payload.get("nonce", b""), "nonce"),
    )
    req.validate()
    return req


def _encode_meta(meta: Union[bytes, Dict[str, Any], None]) -> bytes:
    if meta is None:
        return b""
    if isinstance(meta, dict):
        encoded = cbor2.dumps(meta)
    else:
        encoded = _require_bytes(meta, "meta")
    if len(encoded) > MAX_META_BYTES:
        raise SizeLimitError("meta too large")
    return encoded


def encode_response(resp: ProofResponse) -> bytes:
    meta_bytes = _encode_meta(resp.meta)
    public_inputs = bytes(resp.public_inputs or b"")
    proof = bytes(resp.proof or b"")
    err = resp.err

    normalized = ProofResponse(
        msg_v=resp.msg_v,
        ok=resp.ok,
        t=resp.t,
        schema_v=resp.schema_v,
        d=resp.d,
        public_inputs=public_inputs,
        proof=proof,
        meta=meta_bytes,
        err=err,
    )
    normalized.validate()

    payload = {
        "msg_v": normalized.msg_v,
        "ok": normalized.ok,
        "t": normalized.t,
        "schema_v": normalized.schema_v,
        "d": normalized.d,
        "public_inputs": normalized.public_inputs,
        "proof": normalized.proof,
        "meta": normalized.meta,
        "err": normalized.err,
    }
    blob = cbor2.dumps(payload)
    if len(blob) > RESPONSE_MAX_BYTES:
        raise SizeLimitError("response too large")
    return blob


def decode_response(blob: bytes) -> ProofResponse:
    if not isinstance(blob, (bytes, bytearray)):
        raise SchemaError("response blob must be bytes")
    blob_bytes = bytes(blob)
    if len(blob_bytes) > RESPONSE_MAX_BYTES:
        raise SizeLimitError("response too large")
    payload = cbor2.loads(blob_bytes)
    if not isinstance(payload, dict):
        raise SchemaError("response payload must be a dict")

    public_inputs = payload.get("public_inputs", b"")
    proof = payload.get("proof", b"")
    meta = payload.get("meta", b"")
    err = payload.get("err", None)

    if err is None:
        err_value = None
    else:
        if not isinstance(err, str):
            raise SchemaError("err must be a string")
        err_value = err

    resp = ProofResponse(
        msg_v=int(payload.get("msg_v", -1)),
        ok=bool(payload.get("ok", False)),
        t=payload.get("t", ""),
        schema_v=int(payload.get("schema_v", -1)),
        d=int(payload.get("d", -1)),
        public_inputs=_require_bytes(public_inputs, "public_inputs"),
        proof=_require_bytes(proof, "proof"),
        meta=_require_bytes(meta, "meta"),
        err=err_value,
    )
    resp.validate()
    return resp
