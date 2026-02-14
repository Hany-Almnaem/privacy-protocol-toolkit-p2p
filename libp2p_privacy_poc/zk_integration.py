"""
ZK Integration Module

This module provides the integration layer between privacy analysis and ZK proofs.
It defines ZK-ready data structures and interfaces for future real ZK implementation.

Key responsibilities:
- Prepare data for ZK circuit inputs
- Define ZK-compatible data structures
- Provide interfaces for proof generation
- Handle proof verification and storage
"""

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from libp2p_privacy_poc.mock_zk_proofs import MockZKProofSystem, MockZKProof, ZKProofType
from libp2p_privacy_poc.privacy_analyzer import PrivacyReport, PrivacyRisk


@dataclass
class ZKReadyData:
    """
    Data structure optimized for ZK circuit inputs.
    
    In production, this would be serialized in a format compatible with
    ZK circuits (field elements, commitments, etc.)
    """
    data_type: str
    values: Dict[str, Any] = field(default_factory=dict)
    commitments: Dict[str, str] = field(default_factory=dict)
    public_inputs: Dict[str, Any] = field(default_factory=dict)
    private_inputs: Dict[str, Any] = field(default_factory=dict)
    
    def to_circuit_input(self) -> dict:
        """
        Convert to format suitable for ZK circuit input.
        
        In production, this would convert to field elements for the ZK circuit.
        """
        return {
            "public": self.public_inputs,
            "private": self.private_inputs,
            "commitments": self.commitments,
        }
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "data_type": self.data_type,
            "values": self.values,
            "commitments": self.commitments,
            "public_inputs": self.public_inputs,
            "private_inputs": self.private_inputs,
        }


class ZKDataPreparator:
    """
    Prepares privacy analysis data for ZK proof generation.
    
    This class transforms raw privacy metadata into ZK-ready formats.
    """
    
    def prepare_anonymity_set_data(
        self,
        peer_id: str,
        all_peer_ids: List[str]
    ) -> ZKReadyData:
        """
        Prepare data for anonymity set membership proof.
        
        Args:
            peer_id: The peer ID to prove membership for
            all_peer_ids: All peer IDs in the anonymity set
        
        Returns:
            ZKReadyData ready for circuit input
        """
        # Create commitment to peer_id (hide the actual value)
        peer_commitment = hashlib.sha256(peer_id.encode()).hexdigest()
        
        # Create Merkle tree root of anonymity set (public input)
        merkle_root = self._compute_mock_merkle_root(all_peer_ids)
        
        # Find position in set (private input)
        try:
            position = all_peer_ids.index(peer_id)
        except ValueError:
            position = -1
        
        return ZKReadyData(
            data_type="anonymity_set_membership",
            values={
                "anonymity_set_size": len(all_peer_ids),
                "peer_position": position,
            },
            commitments={
                "peer_id": peer_commitment,
            },
            public_inputs={
                "merkle_root": merkle_root,
                "set_size": len(all_peer_ids),
            },
            private_inputs={
                "peer_id": peer_id,
                "position": position,
                "merkle_proof": self._compute_mock_merkle_proof(all_peer_ids, position),
            }
        )
    
    def prepare_unlinkability_data(
        self,
        session_1_id: str,
        session_2_id: str,
        session_1_metadata: dict,
        session_2_metadata: dict
    ) -> ZKReadyData:
        """
        Prepare data for session unlinkability proof.
        
        Args:
            session_1_id: First session identifier
            session_2_id: Second session identifier
            session_1_metadata: Metadata for first session
            session_2_metadata: Metadata for second session
        
        Returns:
            ZKReadyData ready for circuit input
        """
        # Create commitments to session identifiers
        session_1_commitment = hashlib.sha256(session_1_id.encode()).hexdigest()
        session_2_commitment = hashlib.sha256(session_2_id.encode()).hexdigest()
        
        return ZKReadyData(
            data_type="session_unlinkability",
            values={
                "sessions_unlinkable": session_1_id != session_2_id,
            },
            commitments={
                "session_1": session_1_commitment,
                "session_2": session_2_commitment,
            },
            public_inputs={
                "session_1_commitment": session_1_commitment,
                "session_2_commitment": session_2_commitment,
            },
            private_inputs={
                "session_1_id": session_1_id,
                "session_2_id": session_2_id,
                "session_1_metadata": session_1_metadata,
                "session_2_metadata": session_2_metadata,
            }
        )
    
    def prepare_range_proof_data(
        self,
        value_name: str,
        actual_value: int,
        min_value: int,
        max_value: int
    ) -> ZKReadyData:
        """
        Prepare data for range proof.
        
        Args:
            value_name: Name of the value
            actual_value: The actual value (kept private)
            min_value: Minimum acceptable value
            max_value: Maximum acceptable value
        
        Returns:
            ZKReadyData ready for circuit input
        """
        # Create commitment to actual value
        value_commitment = hashlib.sha256(f"{value_name}_{actual_value}".encode()).hexdigest()
        
        return ZKReadyData(
            data_type="range_proof",
            values={
                "value_name": value_name,
                "in_range": min_value <= actual_value <= max_value,
            },
            commitments={
                "value": value_commitment,
            },
            public_inputs={
                "min_value": min_value,
                "max_value": max_value,
                "value_commitment": value_commitment,
            },
            private_inputs={
                "actual_value": actual_value,
                "blinding_factor": "mock_blinding_factor",
            }
        )
    
    def _compute_mock_merkle_root(self, items: List[str]) -> str:
        """Compute mock Merkle tree root."""
        if not items:
            return hashlib.sha256(b"empty").hexdigest()
        
        # Simple mock: hash all items together
        combined = "".join(sorted(items))
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _compute_mock_merkle_proof(self, items: List[str], position: int) -> List[str]:
        """Compute mock Merkle proof path."""
        if position < 0 or position >= len(items):
            return []
        
        # Mock proof path (would be real Merkle siblings in production)
        return [
            hashlib.sha256(f"sibling_{i}".encode()).hexdigest()
            for i in range(3)  # Assume tree depth of 3
        ]


class ZKPrivacyEnhancer:
    """
    Enhances privacy reports with ZK proofs.
    
    This class takes privacy analysis results and generates ZK proofs
    to provide cryptographic guarantees about privacy properties.
    """
    
    def __init__(self):
        """Initialize the ZK privacy enhancer."""
        self.zk_system = MockZKProofSystem()
        self.data_preparator = ZKDataPreparator()
    
    def enhance_report_with_zk_proofs(
        self,
        report: PrivacyReport,
        peer_ids: List[str],
        session_ids: List[str]
    ) -> Dict[str, List[MockZKProof]]:
        """
        Enhance a privacy report with ZK proofs.
        
        Args:
            report: The privacy report to enhance
            peer_ids: List of all peer IDs in the network
            session_ids: List of session identifiers
        
        Returns:
            Dictionary mapping proof types to generated proofs
        """
        zk_proofs = {
            "anonymity_proofs": [],
            "unlinkability_proofs": [],
            "range_proofs": [],
        }
        
        # Generate anonymity set proofs for each peer
        if peer_ids:
            for peer_id in peer_ids[:5]:  # Limit to first 5 for demo
                proof = self.zk_system.generate_anonymity_set_proof(
                    peer_id=peer_id,
                    anonymity_set_size=len(peer_ids)
                )
                zk_proofs["anonymity_proofs"].append(proof)
        
        # Generate unlinkability proofs for session pairs
        if len(session_ids) >= 2:
            for i in range(min(3, len(session_ids) - 1)):  # Limit to 3 pairs
                proof = self.zk_system.generate_unlinkability_proof(
                    session_1_id=session_ids[i],
                    session_2_id=session_ids[i + 1]
                )
                zk_proofs["unlinkability_proofs"].append(proof)
        
        # Generate range proofs for metrics
        if report.statistics:
            if "total_connections" in report.statistics:
                proof = self.zk_system.generate_range_proof(
                    value_name="connection_count",
                    min_value=10,
                    max_value=1000,
                    actual_value=report.statistics["total_connections"]
                )
                zk_proofs["range_proofs"].append(proof)
        
        return zk_proofs
    
    def generate_privacy_certificate(
        self,
        report: PrivacyReport,
        zk_proofs: Dict[str, List[MockZKProof]]
    ) -> dict:
        """
        Generate a privacy certificate with ZK proofs.
        
        Args:
            report: The privacy report
            zk_proofs: Generated ZK proofs
        
        Returns:
            Privacy certificate with cryptographic guarantees
        """
        # Count valid proofs
        all_proofs = []
        for proof_list in zk_proofs.values():
            all_proofs.extend(proof_list)
        
        valid_proofs = sum(1 for p in all_proofs if p.is_valid)
        
        certificate = {
            "certificate_type": "privacy_analysis_with_zk",
            "timestamp": report.timestamp,
            "overall_risk_score": report.overall_risk_score,
            "zk_proofs": {
                "total_proofs": len(all_proofs),
                "valid_proofs": valid_proofs,
                "by_type": {
                    proof_type: len(proofs)
                    for proof_type, proofs in zk_proofs.items()
                },
            },
            "cryptographic_guarantees": [
                f"Anonymity set membership verified for {len(zk_proofs.get('anonymity_proofs', []))} peers",
                f"Session unlinkability proven for {len(zk_proofs.get('unlinkability_proofs', []))} session pairs",
                f"Range properties verified for {len(zk_proofs.get('range_proofs', []))} metrics",
            ],
            "verification_status": "ALL_PROOFS_VALID" if valid_proofs == len(all_proofs) else "SOME_PROOFS_INVALID",
            "WARNING": "MOCK PROOFS - NOT CRYPTOGRAPHICALLY SECURE",
        }
        
        return certificate
    
    def verify_privacy_certificate(self, certificate: dict) -> bool:
        """
        Verify a privacy certificate.
        
        Args:
            certificate: The certificate to verify
        
        Returns:
            True if certificate is valid
        """
        # Mock verification
        return certificate.get("verification_status") == "ALL_PROOFS_VALID"


class ZKIntegrationInterface:
    """
    High-level interface for ZK integration.
    
    This provides a simple API for adding ZK proofs to privacy analysis.
    """
    
    def __init__(self):
        """Initialize the ZK integration interface."""
        self.enhancer = ZKPrivacyEnhancer()
        self.preparator = ZKDataPreparator()
    
    def analyze_with_zk_proofs(
        self,
        report: PrivacyReport,
        peer_ids: List[str],
        session_ids: List[str]
    ) -> Tuple[PrivacyReport, Dict[str, List[MockZKProof]], dict]:
        """
        Perform privacy analysis with ZK proof generation.
        
        Args:
            report: Privacy analysis report
            peer_ids: List of peer IDs
            session_ids: List of session IDs
        
        Returns:
            Tuple of (report, zk_proofs, certificate)
        """
        # Generate ZK proofs
        zk_proofs = self.enhancer.enhance_report_with_zk_proofs(
            report, peer_ids, session_ids
        )
        
        # Generate privacy certificate
        certificate = self.enhancer.generate_privacy_certificate(
            report, zk_proofs
        )
        
        return report, zk_proofs, certificate
    
    def export_zk_enhanced_report(
        self,
        report: PrivacyReport,
        zk_proofs: Dict[str, List[MockZKProof]],
        certificate: dict
    ) -> dict:
        """
        Export ZK-enhanced report in JSON format.
        
        Args:
            report: Privacy report
            zk_proofs: Generated ZK proofs
            certificate: Privacy certificate
        
        Returns:
            Complete ZK-enhanced report
        """
        return {
            "privacy_report": report.to_dict(),
            "zk_proofs": {
                proof_type: [p.to_dict() for p in proofs]
                for proof_type, proofs in zk_proofs.items()
            },
            "privacy_certificate": certificate,
            "metadata": {
                "version": "0.1.0",
                "proof_system": "MOCK (PySnark2 in production)",
                "WARNING": "MOCK IMPLEMENTATION - NOT PRODUCTION READY",
            }
        }


_PHASE2B_PEER_ID_DOMAIN = b"LIBP2P_PRIVACY_PEER_ID_SCALAR_V1"
_PHASE2B_BLINDING_DOMAIN = b"LIBP2P_PRIVACY_PHASE2B_BLINDING_V1"


def _collect_peer_ids(collector) -> List[str]:
    peer_ids = set()
    if getattr(collector, "peers", None):
        peer_ids.update(collector.peers.keys())
    if getattr(collector, "connections", None):
        peer_ids.update(meta.peer_id for meta in collector.connections.values())
    if getattr(collector, "connection_history", None):
        peer_ids.update(meta.peer_id for meta in collector.connection_history)
    return sorted(peer_ids)


def _select_session_id(collector, peer_id: str) -> str:
    session_id = None
    if getattr(collector, "active_sessions", None):
        matching = sorted(
            sid for sid in collector.active_sessions
            if sid.startswith(f"{peer_id}_")
        )
        if matching:
            session_id = matching[0]
        else:
            session_id = sorted(collector.active_sessions)[0]

    if session_id is None and getattr(collector, "connections", None):
        matching = sorted(
            sid for sid, meta in collector.connections.items()
            if meta.peer_id == peer_id
        )
        if matching:
            session_id = matching[0]

    if session_id is None:
        timestamps = []
        if getattr(collector, "connections", None):
            timestamps.extend(
                meta.timestamp_start
                for meta in collector.connections.values()
                if meta.peer_id == peer_id
            )
        if getattr(collector, "connection_history", None):
            timestamps.extend(
                meta.timestamp_start
                for meta in collector.connection_history
                if meta.peer_id == peer_id
            )
        peer_meta = getattr(collector, "peers", {}).get(peer_id)
        if peer_meta is not None:
            timestamps.append(getattr(peer_meta, "first_seen", 0))
        timestamp = min(timestamps) if timestamps else 0
        session_id = f"{peer_id}:{int(timestamp)}"

    return session_id


def generate_real_commitment_proof(collector) -> Dict[str, Any]:
    """
    Generate and verify a real Pedersen+Schnorr commitment-opening proof.

    Returns a dict with proof metadata and verification result. On failure,
    returns verified=False and an error message without raising.
    """
    result = {
        "backend": "pedersen",
        "statement": "commitment_opening_pok_v1",
        "peer_id": None,
        "session_id": None,
        "verified": False,
        "error": None,
    }

    try:
        if collector is None:
            raise ValueError("collector is required")

        peer_id = None
        if getattr(collector, "peers", None):
            peer_id = sorted(collector.peers.keys())[0]
        elif getattr(collector, "connections", None):
            peers = {meta.peer_id for meta in collector.connections.values()}
            if peers:
                peer_id = sorted(peers)[0]
        elif getattr(collector, "connection_history", None):
            peers = {meta.peer_id for meta in collector.connection_history}
            if peers:
                peer_id = sorted(peers)[0]

        if not peer_id:
            raise ValueError("no peers available for real ZK proof")

        result["peer_id"] = peer_id

        session_id = None
        if getattr(collector, "active_sessions", None):
            matching = sorted(
                sid for sid in collector.active_sessions
                if sid.startswith(f"{peer_id}_")
            )
            if matching:
                session_id = matching[0]
            else:
                session_id = sorted(collector.active_sessions)[0]

        if session_id is None and getattr(collector, "connections", None):
            matching = sorted(
                sid for sid, meta in collector.connections.items()
                if meta.peer_id == peer_id
            )
            if matching:
                session_id = matching[0]

        if session_id is None:
            timestamps = []
            if getattr(collector, "connections", None):
                timestamps.extend(
                    meta.timestamp_start
                    for meta in collector.connections.values()
                    if meta.peer_id == peer_id
                )
            if getattr(collector, "connection_history", None):
                timestamps.extend(
                    meta.timestamp_start
                    for meta in collector.connection_history
                    if meta.peer_id == peer_id
                )
            peer_meta = getattr(collector, "peers", {}).get(peer_id)
            if peer_meta is not None:
                timestamps.append(getattr(peer_meta, "first_seen", 0))
            timestamp = min(timestamps) if timestamps else 0
            session_id = f"{peer_id}:{int(timestamp)}"

        result["session_id"] = session_id

        from libp2p_privacy_poc.privacy_protocol.factory import get_zk_backend
        from libp2p_privacy_poc.privacy_protocol.types import ProofContext

        ctx = ProofContext(
            peer_id=peer_id,
            session_id=session_id,
            metadata={"source": "real_zk_integration"},
        )
        backend = get_zk_backend(prefer="pedersen")
        if not hasattr(backend, "generate_commitment_opening_proof"):
            raise AttributeError(
                "backend does not support commitment opening proofs"
            )

        proof = backend.generate_commitment_opening_proof(ctx)
        is_valid = backend.verify_proof(proof)
        result["verified"] = bool(is_valid)
        return result

    except Exception as exc:
        result["error"] = str(exc)
        print(f"Warning: real ZK proof unavailable: {exc}")
        return result


def generate_real_phase2b_proofs(collector) -> List[Dict[str, Any]]:
    """
    Generate and verify Phase 2B proofs (membership, unlinkability, continuity).

    Returns a list of proof result dicts. On failure, each result includes
    verified=False and an error message without raising.
    """
    statement_order = [
        "anon_set_membership_v1",
        "session_unlinkability_v1",
        "identity_continuity_v1",
    ]
    results: List[Dict[str, Any]] = []

    def _new_result(statement: str) -> Dict[str, Any]:
        return {
            "backend": "pedersen",
            "statement": statement,
            "peer_id": None,
            "session_id": None,
            "verified": False,
            "error": None,
        }

    try:
        if collector is None:
            raise ValueError("collector is required")

        peer_ids = _collect_peer_ids(collector)
        if not peer_ids:
            raise ValueError("no peers available for Phase 2B proofs")

        peer_id = peer_ids[0]
        session_id = _select_session_id(collector, peer_id)

        from petlib.bn import Bn

        from libp2p_privacy_poc.privacy_protocol.factory import get_zk_backend
        from libp2p_privacy_poc.privacy_protocol.merkle import (
            hash_leaf,
            build_tree,
            DOMAIN_SEPARATORS_2B,
        )
        from libp2p_privacy_poc.privacy_protocol.pedersen import membership as membership_module
        from libp2p_privacy_poc.privacy_protocol.statements import StatementType
        from libp2p_privacy_poc.privacy_protocol.types import ProofContext

        backend = get_zk_backend(prefer="pedersen")
        required_methods = (
            "generate_membership_proof",
            "verify_membership_proof",
            "generate_unlinkability_proof",
            "verify_unlinkability_proof",
            "generate_continuity_proof",
            "verify_continuity_proof",
        )
        for method in required_methods:
            if not hasattr(backend, method):
                raise AttributeError(f"backend missing {method}")

        order = membership_module.order
        g = membership_module.g
        h = membership_module.h

        def _derive_scalar(domain_sep: bytes, label: str) -> Bn:
            digest = hashlib.sha256(domain_sep + label.encode("utf-8")).digest()
            scalar = Bn.from_binary(digest) % order
            if int(scalar) == 0:
                scalar = Bn.from_num(1)
            return scalar

        identity_scalars = {
            pid: _derive_scalar(_PHASE2B_PEER_ID_DOMAIN, pid)
            for pid in peer_ids
        }
        blinding_membership = {
            pid: _derive_scalar(_PHASE2B_BLINDING_DOMAIN, f"{pid}:membership")
            for pid in peer_ids
        }

        commitments = [
            ((identity_scalars[pid] * g) + (blinding_membership[pid] * h)).export()
            for pid in peer_ids
        ]
        leaves = [
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], commitment)
            for commitment in commitments
        ]
        root, paths = build_tree(leaves)
        index = peer_ids.index(peer_id)
        merkle_path = paths[index]

        def _context(statement: str) -> ProofContext:
            return ProofContext(
                peer_id=peer_id,
                session_id=session_id,
                metadata={"source": "real_phase2b_integration", "statement": statement},
                timestamp=0.0,
            )

        membership_ctx = _context(StatementType.ANON_SET_MEMBERSHIP.value)
        unlinkability_ctx = _context(StatementType.SESSION_UNLINKABILITY.value)
        continuity_ctx = _context(StatementType.IDENTITY_CONTINUITY.value)

        membership_blinding = blinding_membership[peer_id]
        unlinkability_blinding = _derive_scalar(
            _PHASE2B_BLINDING_DOMAIN, f"{peer_id}:unlinkability"
        )
        continuity_blinding_1 = _derive_scalar(
            _PHASE2B_BLINDING_DOMAIN, f"{peer_id}:continuity_1"
        )
        continuity_blinding_2 = _derive_scalar(
            _PHASE2B_BLINDING_DOMAIN, f"{peer_id}:continuity_2"
        )

        def _finalize(result: Dict[str, Any], verified: bool) -> Dict[str, Any]:
            result["peer_id"] = peer_id
            result["session_id"] = session_id
            result["verified"] = bool(verified)
            return result

        # Membership proof
        result = _new_result(StatementType.ANON_SET_MEMBERSHIP.value)
        try:
            proof = backend.generate_membership_proof(
                identity_scalar=identity_scalars[peer_id],
                blinding=membership_blinding,
                merkle_path=merkle_path,
                root=root,
                context=membership_ctx,
            )
            verified = backend.verify_membership_proof(proof)
            results.append(_finalize(result, verified))
        except Exception as exc:
            result["peer_id"] = peer_id
            result["session_id"] = session_id
            result["error"] = str(exc)
            results.append(result)
            print(
                "Warning: real Phase 2B membership proof unavailable: "
                f"{exc}"
            )

        # Unlinkability proof
        result = _new_result(StatementType.SESSION_UNLINKABILITY.value)
        try:
            proof = backend.generate_unlinkability_proof(
                identity_scalar=identity_scalars[peer_id],
                blinding=unlinkability_blinding,
                context=unlinkability_ctx,
            )
            verified = backend.verify_unlinkability_proof(proof)
            results.append(_finalize(result, verified))
        except Exception as exc:
            result["peer_id"] = peer_id
            result["session_id"] = session_id
            result["error"] = str(exc)
            results.append(result)
            print(
                "Warning: real Phase 2B unlinkability proof unavailable: "
                f"{exc}"
            )

        # Continuity proof
        result = _new_result(StatementType.IDENTITY_CONTINUITY.value)
        try:
            proof = backend.generate_continuity_proof(
                identity_scalar=identity_scalars[peer_id],
                blinding_1=continuity_blinding_1,
                blinding_2=continuity_blinding_2,
                context=continuity_ctx,
            )
            verified = backend.verify_continuity_proof(proof)
            results.append(_finalize(result, verified))
        except Exception as exc:
            result["peer_id"] = peer_id
            result["session_id"] = session_id
            result["error"] = str(exc)
            results.append(result)
            print(
                "Warning: real Phase 2B continuity proof unavailable: "
                f"{exc}"
            )

        return results

    except Exception as exc:
        for statement in statement_order:
            result = _new_result(statement)
            result["error"] = str(exc)
            results.append(result)
        print(f"Warning: real Phase 2B proofs unavailable: {exc}")
        return results


def generate_snark_phase2b_proofs(
    collector,
    *,
    params_dir: Optional[Path] = None,
    prover_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Generate and verify a SNARK membership proof (Phase 2B subset).

    Returns a list with a single membership proof result. On failure, returns
    verified=False and an error message without raising.
    """
    result = {
        "backend": "snark",
        "statement": "anon_set_membership_v1",
        "peer_id": None,
        "session_id": None,
        "verified": False,
        "error": None,
    }

    try:
        if collector is None:
            raise ValueError("collector is required")

        peer_ids = _collect_peer_ids(collector)
        if not peer_ids:
            raise ValueError("no peers available for SNARK proof")

        peer_id = peer_ids[0]
        session_id = _select_session_id(collector, peer_id)
        result["peer_id"] = peer_id
        result["session_id"] = session_id

        from petlib.bn import Bn

        from libp2p_privacy_poc.privacy_protocol.pedersen import membership as membership_module
        from libp2p_privacy_poc.privacy_protocol.snark.membership import (
            build_membership_instance_bytes,
        )

        order = membership_module.order
        g = membership_module.g
        h = membership_module.h

        def _derive_scalar(domain_sep: bytes, label: str) -> Bn:
            digest = hashlib.sha256(domain_sep + label.encode("utf-8")).digest()
            scalar = Bn.from_binary(digest) % order
            if int(scalar) == 0:
                scalar = Bn.from_num(1)
            return scalar

        snark_depth = 16

        identity_scalar = _derive_scalar(_PHASE2B_PEER_ID_DOMAIN, peer_id)
        blinding = _derive_scalar(_PHASE2B_BLINDING_DOMAIN, f"{peer_id}:snark")

        merkle_path = _derive_snark_merkle_path(peer_id, snark_depth)

        instance_bytes, public_inputs_bytes = build_membership_instance_bytes(
            identity_scalar=identity_scalar,
            blinding=blinding,
            merkle_path=merkle_path,
            depth=snark_depth,
            schema_version=1,
        )

        repo_root = Path(__file__).resolve().parents[1]
        params_dir = Path(params_dir) if params_dir else repo_root / "privacy_circuits/params"
        vk_path = params_dir / f"membership_depth{snark_depth}_vk.bin"
        pk_path = params_dir / f"membership_depth{snark_depth}_pk.bin"

        if not vk_path.exists():
            raise FileNotFoundError(f"missing verifying key: {vk_path}")
        if not pk_path.exists():
            raise FileNotFoundError(f"missing proving key: {pk_path}")

        prover_path = Path(prover_path) if prover_path else _find_snark_prover(repo_root)
        if not prover_path.exists():
            raise FileNotFoundError(f"missing SNARK prover binary: {prover_path}")

        with tempfile.TemporaryDirectory() as tmp_dir:
            instance_path = Path(tmp_dir) / "instance.bin"
            public_inputs_path = Path(tmp_dir) / "public_inputs.bin"
            proof_path = Path(tmp_dir) / "proof.bin"

            instance_path.write_bytes(instance_bytes)
            public_inputs_path.write_bytes(public_inputs_bytes)

            _run_snark_prover(
                prover_path,
                pk_path,
                instance_path,
                proof_path,
                schema="v1",
            )

            import membership_py

            verified = membership_py.verify_membership_v1(
                str(vk_path),
                str(public_inputs_path),
                str(proof_path),
            )

        result["verified"] = bool(verified)
        result["depth"] = snark_depth
        if not result["verified"]:
            result["error"] = "SNARK verification failed"

        return [result]

    except Exception as exc:
        result["error"] = str(exc)
        return [result]


def _find_snark_prover(repo_root: Path) -> Path:
    debug_path = repo_root / "privacy_circuits/target/debug/prove_membership"
    if debug_path.exists():
        return debug_path
    release_path = repo_root / "privacy_circuits/target/release/prove_membership"
    if release_path.exists():
        return release_path
    return debug_path


def _run_snark_prover(
    prover_path: Path,
    proving_key: Path,
    instance_path: Path,
    proof_path: Path,
    *,
    schema: str = "v0",
) -> None:
    command = [
        str(prover_path),
        "--pk",
        str(proving_key),
        "--instance",
        str(instance_path),
        "--proof-out",
        str(proof_path),
    ]
    if schema != "v0":
        command.extend(["--schema", schema])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "unknown prover error"
        raise RuntimeError(f"SNARK prover failed: {stderr}")


def _derive_snark_merkle_path(peer_id: str, depth: int) -> List[Tuple[bytes, bool]]:
    path: List[Tuple[bytes, bool]] = []
    for idx in range(depth):
        digest = hashlib.sha256(f"{peer_id}:snark:{idx}".encode("utf-8")).digest()
        is_left = idx % 2 == 0
        path.append((digest, is_left))
    return path
