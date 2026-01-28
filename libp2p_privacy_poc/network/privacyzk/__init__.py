"""Proof exchange protocol schemas and utilities."""

from .assets import AssetsResolver, FixturePaths, ProverPaths
from .constants import PROTOCOL_ID
from .errors import ProtocolError, SchemaError, SizeLimitError
from .handler import handle_proof_request_bytes
from .client import request_proof
from .protocol import handle_proof_stream, register_privacyzk_protocol
from .messages import ProofRequest, ProofResponse
from .provider import (
    FixtureProofProvider,
    HybridProofProvider,
    ProofProvider,
    ProviderConfig,
    RealProofProvider,
)
from .prover import make_real_prover_callback

__all__ = [
    "AssetsResolver",
    "FixturePaths",
    "ProverPaths",
    "PROTOCOL_ID",
    "ProtocolError",
    "SchemaError",
    "SizeLimitError",
    "ProofRequest",
    "ProofResponse",
    "ProofProvider",
    "ProviderConfig",
    "FixtureProofProvider",
    "RealProofProvider",
    "HybridProofProvider",
    "make_real_prover_callback",
    "handle_proof_request_bytes",
    "handle_proof_stream",
    "register_privacyzk_protocol",
    "request_proof",
]
