from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from ...mock_zk_proofs import MockZKProof, MockZKProofSystem
from ..interfaces import AnonymitySetBackend
from ..types import ProofContext, ZKProof, ZKProofType


class MockZKProofSystemAdapter(AnonymitySetBackend):
    """
    Adapter that exposes the legacy MockZKProofSystem through the new backend interface.

    Notes:
    - This adapter is for backward compatibility and testability.
    - It does NOT provide real cryptographic security.
    """

    _BACKEND_NAME = "MockZKProofSystemAdapter"
    _BACKEND_VERSION = "0.1.0"
    _COMMITMENT_LEN = 32

    def __init__(self) -> None:
        self._legacy = MockZKProofSystem()
        self._members: list[Any] = []
        self._parameters: Dict[str, Any] = {}
        self._proof_type_value = ZKProofType.ANONYMITY_SET_MEMBERSHIP.value

    @property
    def backend_name(self) -> str:
        return self._BACKEND_NAME

    @property
    def backend_version(self) -> str:
        return self._BACKEND_VERSION

    def setup_anonymity_set(
        self, members: list, parameters: Optional[Dict[str, Any]] = None
    ) -> None:
        if not isinstance(members, list):
            raise ValueError("members must be a list")
        self._members = list(members)
        self._parameters = dict(parameters) if parameters else {}

    def generate_proof(
        self,
        context: ProofContext,
        witness: Dict[str, Any],
        public_inputs: Dict[str, Any],
    ) -> ZKProof:
        if not isinstance(context, ProofContext):
            raise TypeError("context must be ProofContext")
        if not isinstance(witness, dict):
            raise ValueError("witness must be a dict")
        if not isinstance(public_inputs, dict):
            raise ValueError("public_inputs must be a dict")

        anonymity_set_size = public_inputs.get("anonymity_set_size")
        if anonymity_set_size is None and isinstance(context.metadata, dict):
            anonymity_set_size = context.metadata.get("anonymity_set_size")
        if anonymity_set_size is None:
            raise ValueError("anonymity_set_size is required")

        actual_position = witness.get("actual_position")
        if actual_position is None:
            actual_position = public_inputs.get("actual_position")

        return self.generate_anonymity_set_proof(
            ctx=context,
            anonymity_set_size=anonymity_set_size,
            actual_position=actual_position,
        )

    def generate_anonymity_set_proof(
        self,
        ctx: ProofContext,
        anonymity_set_size: int,
        actual_position: Optional[int] = None,
    ) -> ZKProof:
        if not isinstance(ctx, ProofContext):
            raise TypeError("ctx must be ProofContext")
        if not isinstance(anonymity_set_size, int):
            raise TypeError("anonymity_set_size must be int")
        if anonymity_set_size <= 0:
            raise ValueError("anonymity_set_size must be positive")
        if actual_position is not None and not isinstance(actual_position, int):
            raise TypeError("actual_position must be int or None")

        mock_proof = self._legacy.generate_anonymity_set_proof(
            peer_id=ctx.peer_id,
            anonymity_set_size=anonymity_set_size,
            actual_position=actual_position,
        )
        return self._convert_mock_proof(mock_proof)

    def verify_proof(
        self, proof: ZKProof, public_inputs: Optional[Dict[str, Any]] = None
    ) -> bool:
        try:
            if not isinstance(proof, ZKProof):
                return False
            if not isinstance(proof.proof_type, str):
                return False
            if proof.proof_type != self._proof_type_value:
                return False
            if not isinstance(proof.commitment, bytes):
                return False
            if len(proof.commitment) != self._COMMITMENT_LEN:
                return False
            if public_inputs is not None and not isinstance(public_inputs, dict):
                return False

            public_inputs_dict = proof.public_inputs
            if not isinstance(public_inputs_dict, dict):
                return False
            if public_inputs_dict.get("adapter") != "mock":
                return False
            if public_inputs_dict.get("v") != 1:
                return False

            return True
        except Exception:
            return False

    def batch_verify(self, proofs: List[ZKProof]) -> bool:
        if proofs is None:
            return True
        if not isinstance(proofs, list):
            return False
        for proof in proofs:
            if not self.verify_proof(proof):
                return False
        return True

    def get_backend_info(self) -> Dict[str, Any]:
        return {
            "name": self.backend_name,
            "version": self.backend_version,
            "adapter": "mock",
            "legacy_backend": "MockZKProofSystem",
            "features": ["anonymity_set_membership", "batch_verify"],
            "security": "mock_only",
        }

    @staticmethod
    def _canonical_proof_type(value: Any) -> str:
        if hasattr(value, "value"):
            proof_type = value.value
        else:
            proof_type = value
        if isinstance(proof_type, ZKProofType):
            return proof_type.value
        return str(proof_type)

    @staticmethod
    def _stable_mock_repr(mock_proof: MockZKProof) -> bytes:
        if hasattr(mock_proof, "to_dict"):
            data = mock_proof.to_dict()
        else:
            data = {"proof_type": str(getattr(mock_proof, "proof_type", "unknown"))}
        encoded = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return encoded

    def _commitment_from_mock_proof(self, mock_proof: MockZKProof) -> bytes:
        mock_hash = getattr(mock_proof, "mock_proof_hash", None)
        if isinstance(mock_hash, str) and mock_hash:
            source = mock_hash.encode("utf-8")
        elif isinstance(mock_hash, (bytes, bytearray)) and mock_hash:
            source = bytes(mock_hash)
        else:
            source = self._stable_mock_repr(mock_proof)
        return hashlib.sha256(source).digest()

    def _convert_mock_proof(self, mock_proof: MockZKProof) -> ZKProof:
        proof_type = self._canonical_proof_type(
            getattr(mock_proof, "proof_type", "unknown")
        )
        commitment = self._commitment_from_mock_proof(mock_proof)

        public_inputs: Dict[str, Any] = {}
        legacy_inputs = getattr(mock_proof, "public_inputs", None)
        if isinstance(legacy_inputs, dict):
            public_inputs.update(legacy_inputs)
        public_inputs["adapter"] = "mock"
        public_inputs["v"] = 1

        timestamp = getattr(mock_proof, "timestamp", None)
        if not isinstance(timestamp, (int, float)):
            timestamp = 0.0

        return ZKProof(
            proof_type=proof_type,
            commitment=commitment,
            challenge=b"",
            response=b"",
            public_inputs=public_inputs,
            timestamp=timestamp,
        )
