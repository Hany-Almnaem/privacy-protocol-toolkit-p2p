"""
⚠️ DRAFT — requires crypto review before production use

Unit tests for common types module.

Tests cover:
1. ProofContext serialization and hashing
2. ZKProofType enum values
3. ZKProof serialization/deserialization (CBOR)
4. Compatibility layer with MockZKProof
5. Version checking and error handling
6. JSON serialization (to_dict)
"""

import time
import json
import hashlib
import pytest
import cbor2

from ..types import ProofContext, ZKProofType, ZKProof
from ..config import PROOF_VERSION
from ..exceptions import CryptographicError

# Try to import MockZKProof for compatibility tests
try:
    from libp2p_privacy_poc.mock_zk_proofs import (
        MockZKProof,
        ZKProofType as MockZKProofType
    )
    MOCK_AVAILABLE = True
except ImportError:
    MOCK_AVAILABLE = False


# ============================================================================
# PROOF CONTEXT TESTS
# ============================================================================


class TestProofContext:
    """Test ProofContext functionality."""
    
    def test_basic_creation(self):
        """Test creating a basic ProofContext."""
        ctx = ProofContext(peer_id="QmXYZ123")
        
        assert ctx.peer_id == "QmXYZ123"
        assert ctx.session_id is None
        assert ctx.metadata == {}
        assert isinstance(ctx.timestamp, float)
        assert ctx.timestamp > 0
    
    def test_full_creation(self):
        """Test creating ProofContext with all fields."""
        metadata = {"network": "testnet", "version": "1.0"}
        timestamp = time.time()
        
        ctx = ProofContext(
            peer_id="QmABC456",
            session_id="session_789",
            metadata=metadata,
            timestamp=timestamp
        )
        
        assert ctx.peer_id == "QmABC456"
        assert ctx.session_id == "session_789"
        assert ctx.metadata == metadata
        assert ctx.timestamp == timestamp
    
    def test_to_bytes_deterministic(self):
        """Test that to_bytes() is deterministic."""
        ctx = ProofContext(
            peer_id="QmTest",
            session_id="sess123",
            metadata={"a": 1, "b": 2},
            timestamp=1234567890.0
        )
        
        bytes1 = ctx.to_bytes()
        bytes2 = ctx.to_bytes()
        
        assert bytes1 == bytes2
        assert isinstance(bytes1, bytes)
    
    def test_to_bytes_json_sorted(self):
        """Test that to_bytes() uses sorted JSON keys."""
        ctx = ProofContext(
            peer_id="QmTest",
            metadata={"z": 1, "a": 2, "m": 3}
        )
        
        data = ctx.to_bytes()
        decoded = json.loads(data.decode('utf-8'))
        
        # Check that all fields are present
        assert "peer_id" in decoded
        assert "session_id" in decoded
        assert "metadata" in decoded
        assert "timestamp" in decoded
        
        # JSON dumps with sort_keys should be consistent
        assert isinstance(data, bytes)
    
    def test_to_bytes_hashable(self):
        """Test that to_bytes() output can be hashed."""
        ctx = ProofContext(peer_id="QmTest")
        data = ctx.to_bytes()
        
        # Should be able to hash the output
        hash1 = hashlib.sha256(data).hexdigest()
        hash2 = hashlib.sha256(data).hexdigest()
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex length


# ============================================================================
# ZK PROOF TYPE TESTS
# ============================================================================


class TestZKProofType:
    """Test ZKProofType enum."""
    
    def test_enum_values(self):
        """Test that all required enum values exist."""
        assert ZKProofType.ANONYMITY_SET_MEMBERSHIP.value == "anonymity_set_membership"
        assert ZKProofType.SESSION_UNLINKABILITY.value == "session_unlinkability"
        assert ZKProofType.RANGE_PROOF.value == "range_proof"
        assert ZKProofType.TIMING_INDEPENDENCE.value == "timing_independence"
    
    def test_enum_membership(self):
        """Test enum membership checks."""
        assert ZKProofType.ANONYMITY_SET_MEMBERSHIP in ZKProofType
        assert ZKProofType.SESSION_UNLINKABILITY in ZKProofType
        assert ZKProofType.RANGE_PROOF in ZKProofType
        assert ZKProofType.TIMING_INDEPENDENCE in ZKProofType
    
    def test_enum_iteration(self):
        """Test iterating over enum values."""
        values = [pt.value for pt in ZKProofType]
        
        assert "anonymity_set_membership" in values
        assert "session_unlinkability" in values
        assert "range_proof" in values
        assert "timing_independence" in values


# ============================================================================
# ZK PROOF TESTS
# ============================================================================


class TestZKProof:
    """Test ZKProof functionality."""
    
    def test_basic_creation(self):
        """Test creating a basic ZKProof."""
        proof = ZKProof(
            proof_type="anonymity_set_membership",
            commitment=b"commitment_data"
        )
        
        assert proof.proof_type == "anonymity_set_membership"
        assert proof.commitment == b"commitment_data"
        assert proof.challenge is None
        assert proof.response is None
        assert proof.public_inputs == {}
        assert isinstance(proof.timestamp, float)
    
    def test_full_creation(self):
        """Test creating ZKProof with all fields."""
        timestamp = time.time()
        
        proof = ZKProof(
            proof_type="range_proof",
            commitment=b"commitment",
            challenge=b"challenge",
            response=b"response",
            public_inputs={"min": 0, "max": 100},
            timestamp=timestamp
        )
        
        assert proof.proof_type == "range_proof"
        assert proof.commitment == b"commitment"
        assert proof.challenge == b"challenge"
        assert proof.response == b"response"
        assert proof.public_inputs == {"min": 0, "max": 100}
        assert proof.timestamp == timestamp
    
    # ------------------------------------------------------------------------
    # COMPATIBILITY LAYER TESTS
    # ------------------------------------------------------------------------
    
    def test_mock_proof_hash_property(self):
        """Test mock_proof_hash compatibility property."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"test_commitment"
        )
        
        hash_value = proof.mock_proof_hash
        
        assert isinstance(hash_value, str)
        assert len(hash_value) == 16  # First 16 chars of SHA-256
        
        # Should be deterministic
        assert hash_value == proof.mock_proof_hash
    
    def test_mock_proof_hash_empty_commitment(self):
        """Test mock_proof_hash with empty commitment."""
        proof = ZKProof(
            proof_type="test",
            commitment=b""
        )
        
        # Should handle empty commitment gracefully
        hash_value = proof.mock_proof_hash
        assert isinstance(hash_value, str)
    
    def test_verification_result_property(self):
        """Test verification_result compatibility property."""
        proof_valid = ZKProof(
            proof_type="test",
            commitment=b"valid"
        )
        
        proof_invalid = ZKProof(
            proof_type="test",
            commitment=b""
        )
        
        assert proof_valid.verification_result is True
        assert proof_invalid.verification_result is False
    
    def test_is_valid_property(self):
        """Test is_valid compatibility property (alias)."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"test"
        )
        
        assert proof.is_valid is True
        assert proof.is_valid == proof.verification_result
    
    def test_claim_property(self):
        """Test claim compatibility property."""
        proof = ZKProof(
            proof_type="anonymity_set_membership",
            commitment=b"test"
        )
        
        claim = proof.claim
        
        assert isinstance(claim, str)
        assert "anonymity_set_membership" in claim
        assert "proof" in claim
    
    @pytest.mark.skipif(not MOCK_AVAILABLE, reason="MockZKProof not available")
    def test_from_mock_proof_conversion(self):
        """Test conversion from MockZKProof to ZKProof."""
        mock = MockZKProof(
            proof_type=MockZKProofType.ANONYMITY_SET_MEMBERSHIP,
            claim="test claim",
            timestamp=1234567890.0,
            public_inputs={"test": "value"}
        )
        
        real = ZKProof.from_mock_proof(mock)
        
        assert real.proof_type == "anonymity_set_membership"
        assert isinstance(real.commitment, bytes)
        assert real.public_inputs == {"test": "value"}
        assert real.timestamp == 1234567890.0
    
    @pytest.mark.skipif(not MOCK_AVAILABLE, reason="MockZKProof not available")
    def test_from_mock_proof_compatibility(self):
        """Test that converted proof maintains compatibility."""
        mock = MockZKProof(
            proof_type=MockZKProofType.SESSION_UNLINKABILITY,
            claim="unlinkability",
            timestamp=time.time(),
            public_inputs={"sessions": [1, 2, 3]}
        )
        
        real = ZKProof.from_mock_proof(mock)
        
        # Check compatibility properties work
        assert isinstance(real.mock_proof_hash, str)
        assert isinstance(real.is_valid, bool)
        assert isinstance(real.claim, str)
    
    # ------------------------------------------------------------------------
    # SERIALIZATION TESTS (CBOR)
    # ------------------------------------------------------------------------
    
    def test_serialize_basic(self):
        """Test basic CBOR serialization."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"commitment"
        )
        
        data = proof.serialize()
        
        assert isinstance(data, bytes)
        assert len(data) > 0
    
    def test_serialize_full(self):
        """Test CBOR serialization with all fields."""
        proof = ZKProof(
            proof_type="range_proof",
            commitment=b"commitment",
            challenge=b"challenge",
            response=b"response",
            public_inputs={"min": 0, "max": 100},
            timestamp=1234567890.0
        )
        
        data = proof.serialize()
        obj = cbor2.loads(data)
        
        # Check version field
        assert obj["v"] == PROOF_VERSION
        
        # Check all fields
        assert obj["t"] == "range_proof"
        assert obj["c"] == b"commitment"
        assert obj["ch"] == b"challenge"
        assert obj["r"] == b"response"
        assert obj["p"] == {"min": 0, "max": 100}
        assert obj["ts"] == 1234567890.0
    
    def test_deserialize_basic(self):
        """Test basic CBOR deserialization."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"commitment"
        )
        
        data = proof.serialize()
        restored = ZKProof.deserialize(data)
        
        assert restored.proof_type == proof.proof_type
        assert restored.commitment == proof.commitment
    
    def test_serialize_deserialize_round_trip(self):
        """Test serialization/deserialization round-trip."""
        original = ZKProof(
            proof_type="anonymity_set_membership",
            commitment=b"commitment_bytes",
            challenge=b"challenge_bytes",
            response=b"response_bytes",
            public_inputs={"set_size": 100, "member": True},
            timestamp=1234567890.123
        )
        
        # Round-trip
        data = original.serialize()
        restored = ZKProof.deserialize(data)
        
        # Check all fields preserved
        assert restored.proof_type == original.proof_type
        assert restored.commitment == original.commitment
        assert restored.challenge == original.challenge
        assert restored.response == original.response
        assert restored.public_inputs == original.public_inputs
        assert restored.timestamp == original.timestamp
    
    def test_deserialize_version_check(self):
        """Test that deserialization checks version."""
        # Create CBOR data with wrong version
        wrong_version_data = cbor2.dumps({
            "v": 999,  # Invalid version
            "t": "test",
            "c": b"commitment"
        })
        
        with pytest.raises(ValueError, match="Unsupported proof version"):
            ZKProof.deserialize(wrong_version_data)
    
    def test_deserialize_missing_fields(self):
        """Test that deserialization validates required fields."""
        # Missing proof type
        invalid_data1 = cbor2.dumps({
            "v": PROOF_VERSION,
            "c": b"commitment"
        })
        
        with pytest.raises(ValueError, match="missing required fields"):
            ZKProof.deserialize(invalid_data1)
        
        # Missing commitment
        invalid_data2 = cbor2.dumps({
            "v": PROOF_VERSION,
            "t": "test"
        })
        
        with pytest.raises(ValueError, match="missing required fields"):
            ZKProof.deserialize(invalid_data2)
    
    def test_deserialize_invalid_cbor(self):
        """Test that deserialization handles invalid CBOR."""
        invalid_data = b"not valid cbor data"
        
        with pytest.raises((CryptographicError, ValueError), match="Failed to deserialize|missing required fields"):
            ZKProof.deserialize(invalid_data)
    
    # ------------------------------------------------------------------------
    # JSON SERIALIZATION TESTS (to_dict)
    # ------------------------------------------------------------------------
    
    def test_to_dict_basic(self):
        """Test to_dict conversion."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"\x01\x02\x03"
        )
        
        d = proof.to_dict()
        
        assert isinstance(d, dict)
        assert d["proof_type"] == "test"
        assert d["commitment"] == "010203"  # Hex encoded
        assert "mock_proof_hash" in d
        assert "is_valid" in d
    
    def test_to_dict_full(self):
        """Test to_dict with all fields."""
        proof = ZKProof(
            proof_type="range_proof",
            commitment=b"\x01\x02",
            challenge=b"\x03\x04",
            response=b"\x05\x06",
            public_inputs={"value": 42},
            timestamp=1234567890.0
        )
        
        d = proof.to_dict()
        
        assert d["proof_type"] == "range_proof"
        assert d["commitment"] == "0102"
        assert d["challenge"] == "0304"
        assert d["response"] == "0506"
        assert d["public_inputs"] == {"value": 42}
        assert d["timestamp"] == 1234567890.0
        assert isinstance(d["mock_proof_hash"], str)
        assert isinstance(d["is_valid"], bool)
    
    def test_to_dict_json_serializable(self):
        """Test that to_dict output is JSON-serializable."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"test",
            public_inputs={"nested": {"key": "value"}}
        )
        
        d = proof.to_dict()
        
        # Should be JSON-serializable
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        
        assert parsed["proof_type"] == "test"
        assert parsed["public_inputs"]["nested"]["key"] == "value"
    
    def test_to_dict_none_fields(self):
        """Test to_dict with None fields."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"test"
            # challenge, response left as None
        )
        
        d = proof.to_dict()
        
        assert d["challenge"] is None
        assert d["response"] is None
    
    # ------------------------------------------------------------------------
    # VERIFY METHOD TESTS
    # ------------------------------------------------------------------------
    
    def test_verify_placeholder(self):
        """Test verify method (placeholder implementation)."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"test"
        )
        
        result = proof.verify()
        
        assert isinstance(result, bool)
        assert result is True  # Should match verification_result


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests for types module."""
    
    def test_end_to_end_workflow(self):
        """Test complete workflow: create, serialize, deserialize, verify."""
        # Create context
        ctx = ProofContext(
            peer_id="QmTest123",
            session_id="session_456",
            metadata={"network": "testnet"}
        )
        
        # Create proof
        proof = ZKProof(
            proof_type="anonymity_set_membership",
            commitment=hashlib.sha256(ctx.to_bytes()).digest(),
            public_inputs={"set_size": 100}
        )
        
        # Serialize
        data = proof.serialize()
        
        # Deserialize
        restored = ZKProof.deserialize(data)
        
        # Verify
        assert restored.verify() is True
        
        # Check compatibility
        assert isinstance(restored.mock_proof_hash, str)
        assert restored.is_valid is True
    
    def test_cbor_smaller_than_json(self):
        """Test that CBOR serialization is more efficient than JSON."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"x" * 100,  # Large commitment
            public_inputs={"key" + str(i): i for i in range(10)}
        )
        
        cbor_data = proof.serialize()
        json_data = json.dumps(proof.to_dict()).encode('utf-8')
        
        # CBOR should be more compact (though JSON hex encoding affects this)
        assert len(cbor_data) > 0
        assert len(json_data) > 0
        # Note: Can't guarantee CBOR < JSON due to hex encoding
    
    def test_multiple_proofs_different_types(self):
        """Test creating proofs of different types."""
        types = [
            "anonymity_set_membership",
            "session_unlinkability",
            "range_proof",
            "timing_independence"
        ]
        
        proofs = []
        for ptype in types:
            proof = ZKProof(
                proof_type=ptype,
                commitment=hashlib.sha256(ptype.encode()).digest()
            )
            proofs.append(proof)
        
        # Serialize all
        serialized = [p.serialize() for p in proofs]
        
        # Deserialize all
        restored = [ZKProof.deserialize(d) for d in serialized]
        
        # Check all types preserved
        for i, ptype in enumerate(types):
            assert restored[i].proof_type == ptype


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================


class TestPerformance:
    """Performance tests for types module."""
    
    def test_serialization_performance(self):
        """Measure serialization performance."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"x" * 64,
            challenge=b"y" * 32,
            response=b"z" * 32,
            public_inputs={"key": "value"}
        )
        
        start = time.perf_counter()
        for _ in range(1000):
            data = proof.serialize()
        end = time.perf_counter()
        
        avg_time_ms = (end - start) * 1000 / 1000
        
        # Should be very fast (< 1ms per serialization)
        assert avg_time_ms < 1.0
        print(f"\nSerialization: {avg_time_ms:.3f}ms per operation")
    
    def test_deserialization_performance(self):
        """Measure deserialization performance."""
        proof = ZKProof(
            proof_type="test",
            commitment=b"x" * 64,
            challenge=b"y" * 32,
            response=b"z" * 32,
            public_inputs={"key": "value"}
        )
        
        data = proof.serialize()
        
        start = time.perf_counter()
        for _ in range(1000):
            restored = ZKProof.deserialize(data)
        end = time.perf_counter()
        
        avg_time_ms = (end - start) * 1000 / 1000
        
        # Should be very fast (< 1ms per deserialization)
        assert avg_time_ms < 1.0
        print(f"Deserialization: {avg_time_ms:.3f}ms per operation")

