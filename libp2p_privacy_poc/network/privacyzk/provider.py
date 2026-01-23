"""Proof provider implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Protocol

import cbor2

from .assets import AssetsResolver
from .constants import (
    DEFAULT_MEMBERSHIP_DEPTH,
    MAX_META_BYTES,
    MAX_PROOF_BYTES,
    MAX_PUBLIC_INPUTS_BYTES,
    SNARK_SCHEMA_V,
)
from .errors import SchemaError, SizeLimitError
from .messages import ProofRequest, ProofResponse

ProverCallback = Callable[
    [ProofRequest], tuple[bytes, bytes, dict]
]


class ProofProvider(Protocol):
    def get_proof(self, req: ProofRequest) -> ProofResponse:
        ...


@dataclass(frozen=True)
class ProviderConfig:
    prove_mode: str
    base_dir: str = "privacy_circuits/params"
    strict: bool = True


def _encode_meta(meta: dict) -> bytes:
    encoded = cbor2.dumps(meta)
    if len(encoded) > MAX_META_BYTES:
        raise SizeLimitError("meta too large")
    return encoded


def _validate_request(req: ProofRequest, strict: bool) -> None:
    req.validate()
    if not strict:
        return
    if req.schema_v != SNARK_SCHEMA_V:
        raise SchemaError("unsupported schema_v")
    if req.t == "membership":
        if req.d != DEFAULT_MEMBERSHIP_DEPTH:
            raise SchemaError("unsupported membership depth")
    else:
        if req.d != 0:
            raise SchemaError("unsupported depth for statement")


class FixtureProofProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self._config = config
        self._resolver = AssetsResolver(config.base_dir)

    def get_proof(self, req: ProofRequest) -> ProofResponse:
        try:
            _validate_request(req, self._config.strict)
            fixture = self._resolver.resolve_fixture(req.t, req.schema_v, req.d)
            public_inputs = fixture.public_inputs_path.read_bytes()
            proof = fixture.proof_path.read_bytes()

            meta = {
                "prove_mode": "fixture",
                "statement": req.t,
                "schema_v": req.schema_v,
                "depth": req.d,
                "vk_path": str(fixture.vk_path),
                "public_inputs_path": str(fixture.public_inputs_path),
                "proof_path": str(fixture.proof_path),
            }
            return ProofResponse(
                msg_v=req.msg_v,
                ok=True,
                t=req.t,
                schema_v=req.schema_v,
                d=req.d,
                public_inputs=public_inputs,
                proof=proof,
                meta=_encode_meta(meta),
                err=None,
            )
        except (SchemaError, SizeLimitError) as exc:
            meta = {
                "prove_mode": "fixture",
                "statement": req.t,
                "schema_v": req.schema_v,
                "depth": req.d,
                "error": type(exc).__name__,
            }
            return ProofResponse(
                msg_v=req.msg_v,
                ok=False,
                t=req.t,
                schema_v=req.schema_v,
                d=req.d,
                public_inputs=b"",
                proof=b"",
                meta=_encode_meta(meta),
                err=str(exc),
            )


class RealProofProvider:
    def __init__(
        self, config: ProviderConfig, prover: Optional[ProverCallback] = None
    ) -> None:
        self._config = config
        self._prover = prover

    def get_proof(self, req: ProofRequest) -> ProofResponse:
        try:
            _validate_request(req, self._config.strict)
        except (SchemaError, SizeLimitError) as exc:
            meta = {
                "prove_mode": "real",
                "statement": req.t,
                "schema_v": req.schema_v,
                "depth": req.d,
                "available": False,
                "error": type(exc).__name__,
            }
            return ProofResponse(
                msg_v=req.msg_v,
                ok=False,
                t=req.t,
                schema_v=req.schema_v,
                d=req.d,
                public_inputs=b"",
                proof=b"",
                meta=_encode_meta(meta),
                err=str(exc),
            )

        if self._prover is None:
            meta = {
                "prove_mode": "real",
                "statement": req.t,
                "schema_v": req.schema_v,
                "depth": req.d,
                "available": False,
            }
            return ProofResponse(
                msg_v=req.msg_v,
                ok=False,
                t=req.t,
                schema_v=req.schema_v,
                d=req.d,
                public_inputs=b"",
                proof=b"",
                meta=_encode_meta(meta),
                err="real proving not available",
            )

        try:
            public_inputs, proof, meta_dict = self._prover(req)
            if len(public_inputs) > MAX_PUBLIC_INPUTS_BYTES:
                raise SizeLimitError("public_inputs too large")
            if len(proof) > MAX_PROOF_BYTES:
                raise SizeLimitError("proof too large")
            meta = {
                "prove_mode": "real",
                "statement": req.t,
                "schema_v": req.schema_v,
                "depth": req.d,
                "available": True,
                "prover_meta": meta_dict or {},
            }
            return ProofResponse(
                msg_v=req.msg_v,
                ok=True,
                t=req.t,
                schema_v=req.schema_v,
                d=req.d,
                public_inputs=public_inputs,
                proof=proof,
                meta=_encode_meta(meta),
                err=None,
            )
        except SizeLimitError as exc:
            meta = {
                "prove_mode": "real",
                "statement": req.t,
                "schema_v": req.schema_v,
                "depth": req.d,
                "available": True,
                "error": type(exc).__name__,
            }
            return ProofResponse(
                msg_v=req.msg_v,
                ok=False,
                t=req.t,
                schema_v=req.schema_v,
                d=req.d,
                public_inputs=b"",
                proof=b"",
                meta=_encode_meta(meta),
                err=str(exc),
            )
        except Exception as exc:  # pragma: no cover - defensive
            meta = {
                "prove_mode": "real",
                "statement": req.t,
                "schema_v": req.schema_v,
                "depth": req.d,
                "available": True,
                "error": type(exc).__name__,
            }
            return ProofResponse(
                msg_v=req.msg_v,
                ok=False,
                t=req.t,
                schema_v=req.schema_v,
                d=req.d,
                public_inputs=b"",
                proof=b"",
                meta=_encode_meta(meta),
                err="real proving failed",
            )


class HybridProofProvider:
    def __init__(
        self,
        config: ProviderConfig,
        fixture_provider: FixtureProofProvider,
        real_provider: RealProofProvider,
    ) -> None:
        self._config = config
        self._fixture = fixture_provider
        self._real = real_provider

    def get_proof(self, req: ProofRequest) -> ProofResponse:
        if self._config.prove_mode != "prefer-real":
            raise SchemaError("hybrid provider requires prove_mode=prefer-real")

        real_resp = self._real.get_proof(req)
        if real_resp.ok:
            return real_resp

        fixture_resp = self._fixture.get_proof(req)
        if fixture_resp.ok:
            meta = cbor2.loads(fixture_resp.meta) if fixture_resp.meta else {}
            meta["fallback_from"] = "real"
            meta["real_error"] = real_resp.err
            meta_bytes = _encode_meta(meta)
            return ProofResponse(
                msg_v=fixture_resp.msg_v,
                ok=True,
                t=fixture_resp.t,
                schema_v=fixture_resp.schema_v,
                d=fixture_resp.d,
                public_inputs=fixture_resp.public_inputs,
                proof=fixture_resp.proof,
                meta=meta_bytes,
                err=None,
            )

        meta = {
            "prove_mode": "fixture",
            "statement": req.t,
            "schema_v": req.schema_v,
            "depth": req.d,
            "fallback_from": "real",
        }
        return ProofResponse(
            msg_v=req.msg_v,
            ok=False,
            t=req.t,
            schema_v=req.schema_v,
            d=req.d,
            public_inputs=b"",
            proof=b"",
            meta=_encode_meta(meta),
            err="real and fixture failed",
        )
