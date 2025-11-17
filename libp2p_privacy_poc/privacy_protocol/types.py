"""
⚠️ DRAFT — requires crypto review before production use

Common types for zero-knowledge proofs.

This is a PROTOTYPE implementation for testing and validation.
DO NOT use in production without security audit.

This module provides:
1. ProofContext - unified context for proof generation
2. ZKProofType - enum of supported proof types
3. ZKProof - universal proof structure with CBOR serialization

Compatibility Layer:
- Provides properties compatible with MockZKProof
- Supports gradual migration from mock to real cryptography
- Maintains existing API contracts
"""

import time
import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum

try:
    import cbor2
except ImportError:
    raise ImportError(
        "cbor2 is required for proof serialization. "
        "Install with: pip install cbor2"
    )

from .config import PROOF_VERSION, SERIALIZATION_FORMAT
from .exceptions import ProofVerificationError, CryptographicError

# ============================================================================
# PROOF CONTEXT
# ============================================================================


@dataclass
class ProofContext:
    """
    Unified context for proof generation.
    
    Provides consistent context information across all proof types,
    ensuring reproducibility and domain separation.
    
    Attributes:
        peer_id: Unique identifier for the peer generating the proof
        session_id: Optional session identifier for linkability proofs
        metadata: Additional context-specific metadata
        timestamp: Unix timestamp when context was created
    
    Example:
        >>> ctx = ProofContext(
        ...     peer_id="QmXYZ...",
        ...     session_id="session_123",
        ...     metadata={"network": "testnet"}
        ... )
        >>> ctx_bytes = ctx.to_bytes()
    """
    
    peer_id: str
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_bytes(self) -> bytes:
        """
        Serialize context for cryptographic operations.
        
        Uses deterministic JSON encoding with sorted keys to ensure
        consistent hashing across multiple calls.
        
        Returns:
            bytes: Serialized context suitable for hashing
        
        Example:
            >>> ctx = ProofContext(peer_id="QmXYZ")
            >>> ctx_bytes = ctx.to_bytes()
            >>> assert isinstance(ctx_bytes, bytes)
        """
        data = {
            "peer_id": self.peer_id,
            "session_id": self.session_id,
            "metadata": self.metadata,
            "timestamp": self.timestamp
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')


# ============================================================================
# ZK PROOF TYPE ENUM
# ============================================================================


class ZKProofType(Enum):
    """
    Types of zero-knowledge proofs supported.
    
    Each proof type has specific security properties and use cases:
    
    - ANONYMITY_SET_MEMBERSHIP: Prove peer belongs to set without revealing identity
    - SESSION_UNLINKABILITY: Prove sessions are unlinkable across time
    - RANGE_PROOF: Prove value is within range without revealing exact value
    - TIMING_INDEPENDENCE: Prove timing properties without revealing exact timestamps
    """
    
    ANONYMITY_SET_MEMBERSHIP = "anonymity_set_membership"
    SESSION_UNLINKABILITY = "session_unlinkability"
    RANGE_PROOF = "range_proof"
    TIMING_INDEPENDENCE = "timing_independence"


# ============================================================================
# ZK PROOF (WITH COMPATIBILITY LAYER)
# ============================================================================


@dataclass
class ZKProof:
    """
    Universal zero-knowledge proof structure.
    
    ⚠️ REQUIRES CRYPTO REVIEW
    
    This structure supports both real cryptographic proofs (Pedersen + Schnorr)
    and provides compatibility with the existing MockZKProof system.
    
    Real Cryptographic Fields:
        proof_type: Type of proof (from ZKProofType enum)
        commitment: Pedersen commitment (bytes)
        challenge: Fiat-Shamir challenge (bytes, optional)
        response: Schnorr proof response (bytes, optional)
        public_inputs: Public parameters and inputs
        timestamp: Proof generation time
    
    Compatibility Properties (for MockZKProof):
        mock_proof_hash: SHA-256 hash of commitment (property)
        verification_result: Whether proof has valid structure (property)
        is_valid: Alias for verification_result (property)
        claim: Human-readable claim string (property)
    
    Serialization:
        - Primary: CBOR with version field
        - Compatibility: JSON via to_dict()
    
    Example:
        >>> proof = ZKProof(
        ...     proof_type="anonymity_set_membership",
        ...     commitment=b"commitment_bytes",
        ...     public_inputs={"set_size": 100}
        ... )
        >>> serialized = proof.serialize()
        >>> restored = ZKProof.deserialize(serialized)
    """
    
    proof_type: str  # Use string for flexibility (can be ZKProofType.value)
    commitment: bytes  # Pedersen commitment
    challenge: Optional[bytes] = None  # Fiat-Shamir challenge
    response: Optional[bytes] = None  # Prover response (Schnorr)
    public_inputs: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    # ========================================================================
    # COMPATIBILITY LAYER FOR MockZKProof
    # ========================================================================
    
    @property
    def mock_proof_hash(self) -> str:
        """
        Compatibility property: Generate hash like MockZKProof.
        
        Provides a short hash identifier for the proof, compatible with
        existing code that expects MockZKProof.mock_proof_hash.
        
        Returns:
            str: Hex-encoded SHA-256 hash (first 16 characters)
        """
        if not self.commitment:
            return "0" * 16
        return hashlib.sha256(self.commitment).hexdigest()[:16]
    
    @property
    def verification_result(self) -> bool:
        """
        Compatibility property: Basic structural validation.
        
        ⚠️ THIS IS NOT CRYPTOGRAPHIC VERIFICATION
        
        Only checks if the proof has required fields. Real cryptographic
        verification requires calling the backend verifier.
        
        Returns:
            bool: True if proof has commitment, False otherwise
        """
        return self.commitment is not None and len(self.commitment) > 0
    
    @property
    def is_valid(self) -> bool:
        """
        Compatibility property: Alias for verification_result.
        
        Maintained for API compatibility with MockZKProof.is_valid.
        
        Returns:
            bool: Same as verification_result
        """
        return self.verification_result
    
    @property
    def claim(self) -> str:
        """
        Compatibility property: Generate human-readable claim.
        
        Returns:
            str: Description of what the proof claims
        """
        return f"{self.proof_type} proof"
    
    @classmethod
    def from_mock_proof(cls, mock_proof) -> 'ZKProof':
        """
        Create ZKProof from MockZKProof instance.
        
        Enables gradual migration from mock to real cryptographic proofs
        by converting existing MockZKProof objects.
        
        Args:
            mock_proof: Instance of MockZKProof
        
        Returns:
            ZKProof: Converted proof with compatibility
        
        Example:
            >>> from libp2p_privacy_poc.mock_zk_proofs import MockZKProof, ZKProofType
            >>> mock = MockZKProof(
            ...     proof_type=ZKProofType.ANONYMITY_SET_MEMBERSHIP,
            ...     claim="test"
            ... )
            >>> real = ZKProof.from_mock_proof(mock)
        """
        # Extract proof type (handle both enum and string)
        if hasattr(mock_proof, 'proof_type'):
            if hasattr(mock_proof.proof_type, 'value'):
                proof_type = mock_proof.proof_type.value
            else:
                proof_type = str(mock_proof.proof_type)
        else:
            proof_type = "unknown"
        
        # Extract commitment (convert mock hash to bytes)
        if hasattr(mock_proof, 'mock_proof_hash'):
            if isinstance(mock_proof.mock_proof_hash, str):
                commitment = mock_proof.mock_proof_hash.encode('utf-8')
            else:
                commitment = mock_proof.mock_proof_hash
        else:
            commitment = b"mock_commitment"
        
        # Extract public inputs
        public_inputs = {}
        if hasattr(mock_proof, 'public_inputs'):
            public_inputs = mock_proof.public_inputs or {}
        
        # Extract timestamp
        timestamp = time.time()
        if hasattr(mock_proof, 'timestamp'):
            timestamp = mock_proof.timestamp
        
        return cls(
            proof_type=proof_type,
            commitment=commitment,
            public_inputs=public_inputs,
            timestamp=timestamp
        )
    
    # ========================================================================
    # SERIALIZATION (CBOR)
    # ========================================================================
    
    def serialize(self) -> bytes:
        """
        Serialize proof to bytes using CBOR.
        
        CBOR provides efficient binary serialization with:
        - Deterministic encoding
        - Compact size
        - Type preservation
        - Version field for forward compatibility
        
        Returns:
            bytes: CBOR-encoded proof
        
        Raises:
            CryptographicError: If serialization fails
        
        Example:
            >>> proof = ZKProof(proof_type="test", commitment=b"test")
            >>> data = proof.serialize()
            >>> assert isinstance(data, bytes)
        """
        try:
            data = {
                "v": PROOF_VERSION,  # Version field for compatibility
                "t": self.proof_type,
                "c": self.commitment,
                "ch": self.challenge,
                "r": self.response,
                "p": self.public_inputs,
                "ts": self.timestamp
            }
            return cbor2.dumps(data)
        except Exception as e:
            raise CryptographicError(f"Failed to serialize proof: {e}")
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'ZKProof':
        """
        Deserialize proof from CBOR bytes.
        
        Args:
            data: CBOR-encoded proof bytes
        
        Returns:
            ZKProof: Deserialized proof instance
        
        Raises:
            ValueError: If version is unsupported or data is invalid
            CryptographicError: If deserialization fails
        
        Example:
            >>> proof = ZKProof(proof_type="test", commitment=b"test")
            >>> data = proof.serialize()
            >>> restored = ZKProof.deserialize(data)
            >>> assert restored.proof_type == proof.proof_type
        """
        try:
            obj = cbor2.loads(data)
        except Exception as e:
            raise CryptographicError(f"Failed to deserialize proof: {e}")
        
        # Validate that obj is a dict
        if not isinstance(obj, dict):
            raise ValueError("Invalid proof format: missing required fields")
        
        # Check version
        version = obj.get("v", 1)
        if version != PROOF_VERSION:
            raise ValueError(
                f"Unsupported proof version: {version} "
                f"(expected {PROOF_VERSION})"
            )
        
        # Validate required fields
        if "t" not in obj or "c" not in obj:
            raise ValueError("Invalid proof format: missing required fields")
        
        return cls(
            proof_type=obj["t"],
            commitment=obj["c"],
            challenge=obj.get("ch"),
            response=obj.get("r"),
            public_inputs=obj.get("p", {}),
            timestamp=obj.get("ts", time.time())
        )
    
    def to_dict(self) -> dict:
        """
        Convert to dictionary for JSON serialization.
        
        Provides compatibility with systems expecting JSON format.
        Binary fields (commitment, challenge, response) are hex-encoded.
        
        Returns:
            dict: JSON-compatible dictionary
        
        Example:
            >>> proof = ZKProof(proof_type="test", commitment=b"\\x01\\x02")
            >>> d = proof.to_dict()
            >>> assert d["commitment"] == "0102"
        """
        return {
            "proof_type": self.proof_type,
            "commitment": self.commitment.hex() if self.commitment else None,
            "challenge": self.challenge.hex() if self.challenge else None,
            "response": self.response.hex() if self.response else None,
            "public_inputs": self.public_inputs,
            "timestamp": self.timestamp,
            # Compatibility fields
            "mock_proof_hash": self.mock_proof_hash,
            "is_valid": self.is_valid,
            "claim": self.claim
        }
    
    def verify(self) -> bool:
        """
        Verify proof (placeholder - real verification in backend).
        
        ⚠️ THIS IS A PLACEHOLDER
        
        Real verification will be implemented in the Pedersen/Schnorr backend
        (Step 3.2) and will perform actual cryptographic verification:
        1. Validate commitment structure
        2. Recompute Fiat-Shamir challenge
        3. Verify Schnorr proof equation
        4. Check public inputs
        
        For now, returns structural validation only.
        
        Returns:
            bool: True if proof has valid structure
        """
        return self.verification_result

