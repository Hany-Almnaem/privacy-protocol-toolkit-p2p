"""Client utilities for privacy proof exchange."""

from __future__ import annotations

from typing import Any

from .constants import PROTOCOL_ID
from .limits import READ_TIMEOUT, WRITE_TIMEOUT, read_frame, write_frame
from .messages import ProofRequest, ProofResponse, decode_response, encode_request


async def request_proof(
    host: Any, peer_id: Any, req: ProofRequest, *, timeout: float | None = None
) -> ProofResponse:
    frame_timeout = READ_TIMEOUT if timeout is None else timeout
    write_timeout = WRITE_TIMEOUT if timeout is None else timeout
    stream = await host.new_stream(peer_id, [PROTOCOL_ID])
    try:
        request_blob = encode_request(req)
        await write_frame(stream, request_blob, timeout=write_timeout)
        response_blob = await read_frame(stream, timeout=frame_timeout)
        return decode_response(response_blob)
    finally:
        try:
            await stream.close()
        except Exception:
            pass
