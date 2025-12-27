"""
WARNING: DRAFT - requires cryptographic review before production use.

Pedersen commitment backend with Schnorr proofs of commitment opening.

This backend composes:
- Pedersen commitments for value hiding
- Schnorr proofs of knowledge for commitment opening
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import hashlib

from petlib.bn import Bn

from .commitments import CurveParameters, commit, get_cached_curve_params
from .schnorr import generate_schnorr_pok, verify_schnorr_pok
from ..config import (
    DOMAIN_SEPARATORS,
    GROUP_ORDER,
    POINT_SIZE_BYTES,
    SERIALIZATION_FORMAT,
)
from ..exceptions import ProofGenerationError
from ..interfaces import CommitmentOpeningBackend
from ..security import RandomnessSource
from ..types import ProofContext, ZKProof, ZKProofType


class PedersenBackend(CommitmentOpeningBackend):
    """
    Pedersen commitment backend with Schnorr proofs.

    This backend generates proofs that the prover knows an opening for a
    Pedersen commitment bound to a session context. The proof is packaged
    as an "anonymity_set_membership" claim with public_inputs["claim_only"] = True
    to clarify that it does not prove anonymity-set membership yet.

    Example:
        >>> backend = PedersenBackend()
        >>> ctx = ProofContext(peer_id="QmTest123", session_id="session_001")
        >>> proof = backend.generate_commitment_opening_proof(ctx)
        >>> assert backend.verify_proof(proof)
    """

    _BACKEND_NAME = "Pedersen+Schnorr"
    _BACKEND_VERSION = "0.1.0"

    def __init__(self) -> None:
        """Initialize backend with curve parameters and randomness source."""
        self.params: CurveParameters = get_cached_curve_params()
        self.rng = RandomnessSource()
        self._proof_type_value = ZKProofType.ANONYMITY_SET_MEMBERSHIP.value

    @property
    def backend_name(self) -> str:
        """Human-readable backend name."""
        return self._BACKEND_NAME

    @property
    def backend_version(self) -> str:
        """Backend implementation version."""
        return self._BACKEND_VERSION

    @staticmethod
    def _encode_length_prefixed(parts: List[bytes]) -> bytes:
        out = bytearray()
        for part in parts:
            if not isinstance(part, bytes):
                raise TypeError("context parts must be bytes")
            out.extend(len(part).to_bytes(4, "big"))
            out.extend(part)
        return bytes(out)

    def _derive_commitment_value(self, peer_id: str) -> int:
        peer_id_bytes = peer_id.encode("utf-8")
        digest = hashlib.sha256(
            DOMAIN_SEPARATORS["peer_id_scalar"] + peer_id_bytes
        ).digest()
        return int.from_bytes(digest, "big") % GROUP_ORDER

    def _derive_context(
        self, session_id: str, commitment: bytes, proof_type: str
    ) -> bytes:
        domain_sep = DOMAIN_SEPARATORS["commitment_opening_pok"]
        backend_info = f"{self.backend_name}:{self.backend_version}".encode(
            "utf-8"
        )
        context = self._encode_length_prefixed(
            [
                domain_sep,
                backend_info,
                session_id.encode("utf-8"),
                commitment,
                proof_type.encode("utf-8"),
            ]
        )
        return context

    def generate_proof(
        self,
        context: ProofContext,
        witness: Dict[str, Any],
        public_inputs: Dict[str, Any],
    ) -> ZKProof:
        """
        Generate a proof using the generic ProofBackend interface.

        This method delegates to generate_commitment_opening_proof and
        optionally cross-checks session_id from public_inputs.
        """
        if not isinstance(witness, dict):
            raise ValueError("witness must be a dict")

        if not isinstance(public_inputs, dict):
            raise ValueError("public_inputs must be a dict")

        session_id = public_inputs.get("session_id")
        if session_id is not None and session_id != context.session_id:
            raise ValueError("public_inputs session_id mismatch")

        return self.generate_commitment_opening_proof(ctx=context)

    def generate_commitment_opening_proof(self, ctx: ProofContext) -> ZKProof:
        """
        Generate proof of knowledge of a commitment opening.

        Protocol:
        1. Hash peer_id with domain separation to scalar value
        2. Create Pedersen commitment: C = value*G + blinding*H
        3. Generate Schnorr proof of knowledge of (value, blinding)
        4. Package into ZKProof structure as an "anonymity_set_membership"
           claim with public_inputs["claim_only"] = True (no membership proof yet)

        Args:
            ctx: Proof context (provides peer_id, session_id, etc.)

        Returns:
            ZKProof with commitment, challenge, response, and public inputs.

        Raises:
            TypeError: If inputs are wrong types
            ValueError: If inputs are invalid
            ProofGenerationError: For other proof generation failures
        """
        try:
            if not isinstance(ctx, ProofContext):
                raise TypeError("ctx must be ProofContext")

            if not isinstance(ctx.peer_id, str):
                raise TypeError("peer_id must be str")

            if not ctx.peer_id:
                raise ValueError("peer_id cannot be empty")

            if not isinstance(ctx.session_id, str):
                raise TypeError("session_id must be str")

            if not ctx.session_id:
                raise ValueError("session_id cannot be empty")

            peer_id_bytes = ctx.peer_id.encode("utf-8")
            ctx_hash = hashlib.sha256(ctx.to_bytes()).digest()
            peer_id_scalar = int.from_bytes(
                hashlib.sha256(
                    DOMAIN_SEPARATORS["peer_id_scalar"] + peer_id_bytes
                ).digest(),
                "big",
            ) % GROUP_ORDER

            commitment_bytes, blinding = commit(
                value=peer_id_scalar,
                params=self.params,
                randomness_source=self.rng,
            )

            schnorr_proof = generate_schnorr_pok(
                commitment=commitment_bytes,
                value=peer_id_scalar,
                blinding=blinding,
                context=ctx_hash,
                params=self.params,
            )

            A_bytes = schnorr_proof["A"]
            if len(A_bytes) != POINT_SIZE_BYTES:
                raise ProofGenerationError("Invalid announcement size")

            SCALAR_BYTES = self.params.scalar_bytes
            challenge_int = int.from_bytes(schnorr_proof["c"], "big")
            z_v_int = int.from_bytes(schnorr_proof["z_v"], "big")
            z_b_int = int.from_bytes(schnorr_proof["z_b"], "big")
            challenge_bytes = challenge_int.to_bytes(SCALAR_BYTES, "big")
            response_bytes = (
                z_v_int.to_bytes(SCALAR_BYTES, "big")
                + z_b_int.to_bytes(SCALAR_BYTES, "big")
            )

            anonymity_set_size = 1
            if isinstance(ctx.metadata, dict):
                anonymity_set_size = ctx.metadata.get(
                    "anonymity_set_size", anonymity_set_size
                )

            if SERIALIZATION_FORMAT.upper() == "CBOR":
                A_field = A_bytes
            else:
                A_field = A_bytes.hex()

            proof = ZKProof(
                proof_type=self._proof_type_value,
                commitment=commitment_bytes,
                challenge=challenge_bytes,
                response=response_bytes,
                public_inputs={
                    "v": 1,
                    "curve": self.params.curve_name,
                    "anonymity_set_size": anonymity_set_size,
                    "ctx_hash": ctx_hash,
                    "A": A_field,
                    "claim_only": True,
                },
            )

            return proof

        except (ValueError, TypeError):
            raise
        except Exception as exc:
            raise ProofGenerationError(
                f"Proof generation failed: {type(exc).__name__}"
            ) from exc

    def verify_proof(
        self, proof: ZKProof, public_inputs: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Verify commitment opening proof.

        Proofs are claim-only and do not prove anonymity-set membership yet.

        Verification:
        1. Validate proof structure and sizes
        2. Extract Schnorr proof components
        3. Verify Schnorr proof using verify_schnorr_pok()

        Args:
            proof: ZKProof to verify
            public_inputs: Optional public inputs (unused for now)

        Returns:
            True if proof is valid, False otherwise
        """
        try:
            if not isinstance(proof, ZKProof):
                return False

            if proof.proof_type != self._proof_type_value:
                return False

            if not isinstance(proof.commitment, bytes):
                return False

            if len(proof.commitment) != POINT_SIZE_BYTES:
                return False

            if not isinstance(proof.challenge, (bytes, bytearray)):
                return False

            if not isinstance(proof.response, (bytes, bytearray)):
                return False

            public_inputs_dict = proof.public_inputs or {}
            if not isinstance(public_inputs_dict, dict):
                return False

            if public_inputs is not None:
                if not isinstance(public_inputs, dict):
                    return False

            if public_inputs_dict.get("v") != 1:
                return False

            ctx_hash = public_inputs_dict.get("ctx_hash")
            A_field = public_inputs_dict.get("A")

            if not isinstance(ctx_hash, (bytes, bytearray)) or not ctx_hash:
                return False

            if isinstance(A_field, (bytes, bytearray)):
                A_bytes = bytes(A_field)
            elif isinstance(A_field, str):
                try:
                    A_bytes = bytes.fromhex(A_field)
                except ValueError:
                    return False
            else:
                return False

            SCALAR_BYTES = self.params.scalar_bytes

            if len(proof.challenge) != SCALAR_BYTES:
                return False
            if len(proof.response) != 2 * SCALAR_BYTES:
                return False

            z_v = int.from_bytes(proof.response[:SCALAR_BYTES], "big")
            z_b = int.from_bytes(proof.response[SCALAR_BYTES:], "big")
            c = int.from_bytes(proof.challenge, "big")
            schnorr_proof = {
                "A": A_bytes,
                "c": c.to_bytes(SCALAR_BYTES, "big"),
                "z_v": z_v.to_bytes(SCALAR_BYTES, "big"),
                "z_b": z_b.to_bytes(SCALAR_BYTES, "big"),
            }

            return verify_schnorr_pok(
                commitment=proof.commitment,
                proof=schnorr_proof,
                context=bytes(ctx_hash),
                params=self.params,
            )

        except Exception:
            return False

    def generate_membership_proof(
        self,
        identity_scalar: Bn,
        blinding: Bn,
        merkle_path: List[Tuple[bytes, bool]],
        root: bytes,
        context: ProofContext,
    ) -> ZKProof:
        """
        Generate anonymity set membership proof (Phase 2B).

        This is a thin wrapper around membership.py implementation.
        """
        from .membership import (
            generate_membership_proof as _gen,
        )

        ctx_hash = hashlib.sha256(context.to_bytes()).digest()

        return _gen(
            identity_scalar=identity_scalar,
            blinding=blinding,
            merkle_path=merkle_path,
            root=root,
            ctx_hash=ctx_hash,
        )

    def verify_membership_proof(self, proof: ZKProof) -> bool:
        """
        Verify anonymity set membership proof (Phase 2B).
        """
        from .membership import (
            verify_membership_proof as _verify,
        )
        return _verify(proof)

    def generate_unlinkability_proof(
        self,
        identity_scalar: Bn,
        blinding: Bn,
        context: ProofContext,
    ) -> ZKProof:
        """
        Generate session unlinkability proof (Phase 2B).

        Args:
            identity_scalar: Secret identity scalar
            blinding: Fresh blinding for this session (must be unique)
            context: Proof context (contains session/topic info)

        Returns:
            ZKProof with unlinkability statement

        Note:
            Caller is responsible for generating fresh blinding per session.
            Reusing blinding across sessions breaks unlinkability.
        """
        from .unlinkability import (
            generate_unlinkability_proof as _gen,
        )

        ctx_hash = hashlib.sha256(context.to_bytes()).digest()

        return _gen(
            identity_scalar=identity_scalar,
            blinding=blinding,
            ctx_hash=ctx_hash,
        )

    def verify_unlinkability_proof(self, proof: ZKProof) -> bool:
        """
        Verify session unlinkability proof (Phase 2B).
        """
        from .unlinkability import (
            verify_unlinkability_proof as _verify,
        )
        return _verify(proof)

    def generate_continuity_proof(
        self,
        identity_scalar: Bn,
        blinding_1: Bn,
        blinding_2: Bn,
        context: ProofContext,
    ) -> ZKProof:
        """
        Generate identity continuity proof (Phase 2B).

        Args:
            identity_scalar: Shared identity scalar across both commitments
            blinding_1: Blinding for first commitment
            blinding_2: Blinding for second commitment
            context: Proof context

        Returns:
            ZKProof with continuity statement

        Note:
            This proves C1 and C2 share the same identity scalar
            without revealing the identity or blindings.
        """
        from .continuity import (
            generate_continuity_proof as _gen,
        )

        ctx_hash = hashlib.sha256(context.to_bytes()).digest()

        return _gen(
            identity_scalar=identity_scalar,
            blinding_1=blinding_1,
            blinding_2=blinding_2,
            ctx_hash=ctx_hash,
        )

    def verify_continuity_proof(self, proof: ZKProof) -> bool:
        """
        Verify identity continuity proof (Phase 2B).
        """
        from .continuity import (
            verify_continuity_proof as _verify,
        )
        return _verify(proof)

    def batch_verify(self, proofs: List[ZKProof]) -> bool:
        """
        Batch verify multiple proofs (sequential for now).

        Args:
            proofs: List of ZKProof objects

        Returns:
            True if all proofs valid, False if any invalid
        """
        if not isinstance(proofs, list):
            return False

        for proof in proofs:
            if not self.verify_proof(proof):
                return False
        return True

    def get_backend_info(self) -> Dict[str, Any]:
        """
        Get backend metadata and implementation details.

        Returns:
            dict: Backend info (name, version, curve, library, features)
        """
        return {
            "name": self.backend_name,
            "version": self.backend_version,
            "curve": getattr(self.params, "curve", "secp256k1"),
            "library": getattr(self.params, "library", "petlib"),
            "features": [
                "pedersen_commitments",
                "schnorr_proofs",
                "commitment_opening_pok",
                "context_bound_proofs",
            ],
            "performance_targets_ms": {
                "generate_commitment_opening_proof": 15,
                "verify_proof": 3,
                "batch_verify_100": 300,
            },
            "limitations": [
                "sequential_batch_verification",
            ],
        }
