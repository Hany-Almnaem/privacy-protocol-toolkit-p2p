"""Stream handler registration for privacy proof exchange."""

from __future__ import annotations

from typing import Any, Callable

import trio

from .constants import DEFAULT_MEMBERSHIP_DEPTH, MSG_V, PROTOCOL_ID, SNARK_SCHEMA_V
from .errors import SchemaError, SizeLimitError
from .handler import handle_proof_request_bytes
from .limits import READ_TIMEOUT, WRITE_TIMEOUT, read_frame, write_frame
from .messages import ProofResponse, encode_response
from .provider import ProofProvider, _encode_meta

TOTAL_TIMEOUT = 120.0


async def handle_proof_stream(stream: Any, provider: ProofProvider) -> None:
    try:
        with trio.fail_after(TOTAL_TIMEOUT):
            request_blob = await read_frame(stream)
            response_blob = handle_proof_request_bytes(request_blob, provider)
            await write_frame(stream, response_blob)
    except Exception as exc:
        response = _error_response(str(exc))
        try:
            response_blob = encode_response(response)
            await write_frame(stream, response_blob)
        except Exception:
            pass
    finally:
        try:
            await stream.close()
        except Exception:
            pass


def register_privacyzk_protocol(host: Any, provider: ProofProvider) -> None:
    async def _handler(stream: Any) -> None:
        await handle_proof_stream(stream, provider)

    host.set_stream_handler(PROTOCOL_ID, _handler)


def _error_response(err: str) -> ProofResponse:
    meta = {
        "prove_mode": "fixture",
        "statement": "membership",
        "schema_v": SNARK_SCHEMA_V,
        "depth": DEFAULT_MEMBERSHIP_DEPTH,
    }
    return ProofResponse(
        msg_v=MSG_V,
        ok=False,
        t="membership",
        schema_v=SNARK_SCHEMA_V,
        d=DEFAULT_MEMBERSHIP_DEPTH,
        public_inputs=b"",
        proof=b"",
        meta=_encode_meta(meta),
        err=f"protocol error: {err}",
    )
