"""
Privacy Analyzer for py-libp2p

Analyzes collected metadata to detect privacy leaks and assess privacy risks.

Key analysis capabilities:
- Peer linkability detection
- Timing correlation analysis
- Session tracking and unlinkability
- Traffic pattern fingerprinting
- Privacy risk scoring
"""

import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter

from libp2p_privacy_poc.metadata_collector import MetadataCollector, ConnectionMetadata, PeerMetadata


@dataclass
class PrivacyRisk:
    """Represents a detected privacy risk."""
    risk_type: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    affected_peers: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "risk_type": self.risk_type,
            "severity": self.severity,
            "description": self.description,
            "affected_peers": self.affected_peers,
            "confidence": self.confidence,
            "recommendations": self.recommendations,
        }


@dataclass
class PrivacyReport:
    """
    Comprehensive privacy analysis report.
    """
    timestamp: float
    overall_risk_score: float  # 0.0 (safe) to 1.0 (critical)
    risks: List[PrivacyRisk] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    peer_analysis: Dict = field(default_factory=dict)
    timing_analysis: Dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def get_risks_by_severity(self, severity: str) -> List[PrivacyRisk]:
        """Get all risks of a specific severity."""
        return [risk for risk in self.risks if risk.severity == severity]
    
    def get_critical_risks(self) -> List[PrivacyRisk]:
        """Get all critical risks."""
        return self.get_risks_by_severity("critical")
    
    def get_high_risks(self) -> List[PrivacyRisk]:
        """Get all high severity risks."""
        return self.get_risks_by_severity("high")
    
    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = []
        lines.append("=" * 60)
        lines.append("Privacy Analysis Report")
        lines.append("=" * 60)
        lines.append(f"\nOverall Risk Score: {self.overall_risk_score:.2f}/1.00")
        lines.append(f"Risk Level: {self.get_risk_level()}")
        lines.append(f"\nTotal Risks Detected: {len(self.risks)}")
        lines.append(f"  - Critical: {len(self.get_critical_risks())}")
        lines.append(f"  - High: {len(self.get_high_risks())}")
        lines.append(f"  - Medium: {len(self.get_risks_by_severity('medium'))}")
        lines.append(f"  - Low: {len(self.get_risks_by_severity('low'))}")
        
        if self.risks:
            lines.append("\n" + "-" * 60)
            lines.append("Top Privacy Risks:")
            lines.append("-" * 60)
            for i, risk in enumerate(self.risks[:5], 1):
                lines.append(f"\n{i}. [{risk.severity.upper()}] {risk.risk_type}")
                lines.append(f"   {risk.description}")
                lines.append(f"   Confidence: {risk.confidence:.0%}")
        
        if self.recommendations:
            lines.append("\n" + "-" * 60)
            lines.append("Recommendations:")
            lines.append("-" * 60)
            for i, rec in enumerate(self.recommendations[:5], 1):
                lines.append(f"{i}. {rec}")
        
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)
    
    def get_risk_level(self) -> str:
        """
        Get overall risk level based on score.
        
        Returns one of: "CRITICAL", "HIGH", "MEDIUM", or "LOW"
        
        Thresholds:
        - CRITICAL: >= 0.75
        - HIGH: >= 0.5
        - MEDIUM: >= 0.25
        - LOW: < 0.25
        """
        if self.overall_risk_score >= 0.75:
            return "CRITICAL"
        elif self.overall_risk_score >= 0.5:
            return "HIGH"
        elif self.overall_risk_score >= 0.25:
            return "MEDIUM"
        else:
            return "LOW"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "overall_risk_score": self.overall_risk_score,
            "risk_level": self.get_risk_level(),
            "risks": [risk.to_dict() for risk in self.risks],
            "statistics": self.statistics,
            "peer_analysis": self.peer_analysis,
            "timing_analysis": self.timing_analysis,
            "recommendations": self.recommendations,
        }


class PrivacyAnalyzer:
    """
    Analyzes privacy risks in py-libp2p networks.
    
    This analyzer uses collected metadata to detect various privacy leaks:
    - Peer linkability (can connections be linked to the same peer?)
    - Timing correlations (do timing patterns reveal identity?)
    - Session tracking (can sessions be tracked across reconnections?)
    - Traffic fingerprinting (does traffic pattern leak information?)
    """
    
    def __init__(self, metadata_collector: MetadataCollector):
        """
        Initialize the privacy analyzer.
        
        Args:
            metadata_collector: MetadataCollector instance with collected data
        """
        self.collector = metadata_collector
        
        # Analysis thresholds (tunable)
        self.TIMING_CORRELATION_THRESHOLD = 0.7
        self.LINKABILITY_THRESHOLD = 0.6
        self.MIN_ANONYMITY_SET_SIZE = 10
        
    def analyze(self) -> PrivacyReport:
        """
        Perform comprehensive privacy analysis.
        
        Returns:
            PrivacyReport with detected risks and recommendations
        """
        import time
        
        report = PrivacyReport(
            timestamp=time.time(),
            overall_risk_score=0.0  # Will be calculated later
        )
        
        # Collect statistics
        report.statistics = self.collector.get_statistics()
        
        # Run all analysis modules
        report.risks.extend(self._analyze_peer_linkability())
        report.risks.extend(self._analyze_timing_correlations())
        report.risks.extend(self._analyze_session_unlinkability())
        report.risks.extend(self._analyze_anonymity_set())
        report.risks.extend(self._analyze_protocol_fingerprinting())
        report.risks.extend(self._analyze_connection_patterns())
        
        # Perform peer-specific analysis
        report.peer_analysis = self._analyze_peers()
        
        # Perform timing analysis
        report.timing_analysis = self._analyze_timing_patterns()
        
        # Calculate overall risk score
        report.overall_risk_score = self._calculate_overall_risk(report.risks)
        
        # Generate recommendations
        report.recommendations = self._generate_recommendations(report.risks)
        
        return report
    
    def _analyze_peer_linkability(self) -> List[PrivacyRisk]:
        """
        Detect if multiple connections can be linked to the same peer.
        
        Linkability indicators:
        - Same multiaddr used across connections
        - Similar protocol usage patterns
        - Consistent timing patterns
        """
        risks = []
        
        # Group connections by peer
        peer_connections = defaultdict(list)
        for conn in self.collector.connection_history:
            peer_connections[conn.peer_id].append(conn)
        
        for peer_id, connections in peer_connections.items():
            if len(connections) < 2:
                continue
            
            # Check for linkability indicators
            multiaddrs = [conn.multiaddr for conn in connections]
            unique_multiaddrs = len(set(multiaddrs))
            
            # If peer uses same multiaddr repeatedly, it's easily linkable
            if unique_multiaddrs == 1:
                risks.append(PrivacyRisk(
                    risk_type="Peer Linkability",
                    severity="high",
                    description=f"Peer {peer_id[:16]}... uses same multiaddr across {len(connections)} connections",
                    affected_peers=[peer_id],
                    confidence=0.95,
                    recommendations=[
                        "Use different multiaddrs for each connection",
                        "Implement address rotation",
                        "Consider using relay connections for anonymity"
                    ]
                ))
            elif unique_multiaddrs < len(connections) * 0.5:
                risks.append(PrivacyRisk(
                    risk_type="Peer Linkability",
                    severity="medium",
                    description=f"Peer {peer_id[:16]}... reuses multiaddrs frequently",
                    affected_peers=[peer_id],
                    confidence=0.75,
                    recommendations=[
                        "Increase multiaddr diversity",
                        "Implement address rotation policy"
                    ]
                ))
        
        return risks
    
    def _analyze_timing_correlations(self) -> List[PrivacyRisk]:
        """
        Detect timing-based privacy leaks.
        
        Timing correlation indicators:
        - Regular connection intervals (fingerprinting)
        - Synchronized connection/disconnection patterns
        - Predictable activity patterns
        """
        risks = []
        
        if len(self.collector.connection_times) < 3:
            return risks
        
        # Calculate inter-connection intervals
        intervals = []
        for i in range(1, len(self.collector.connection_times)):
            interval = self.collector.connection_times[i] - self.collector.connection_times[i-1]
            intervals.append(interval)
        
        if not intervals:
            return risks
        
        # Check for regular patterns (low variance = predictable)
        mean_interval = statistics.mean(intervals)
        if len(intervals) > 1:
            stdev_interval = statistics.stdev(intervals)
            coefficient_of_variation = stdev_interval / mean_interval if mean_interval > 0 else 0
            
            if coefficient_of_variation < 0.3:  # Low variation = regular pattern
                risks.append(PrivacyRisk(
                    risk_type="Timing Correlation",
                    severity="medium",
                    description=f"Regular connection timing pattern detected (CV: {coefficient_of_variation:.2f})",
                    confidence=0.80,
                    recommendations=[
                        "Add random delays between connections",
                        "Implement timing obfuscation",
                        "Use connection pooling to mask patterns"
                    ]
                ))
        
        # Check for very short intervals (burst pattern)
        short_intervals = [i for i in intervals if i < 1.0]  # Less than 1 second
        if len(short_intervals) > len(intervals) * 0.3:
            risks.append(PrivacyRisk(
                risk_type="Timing Correlation",
                severity="low",
                description=f"Burst connection pattern detected ({len(short_intervals)} rapid connections)",
                confidence=0.65,
                recommendations=[
                    "Space out connection attempts",
                    "Implement connection rate limiting"
                ]
            ))
        
        return risks
    
    def _analyze_session_unlinkability(self) -> List[PrivacyRisk]:
        """
        Assess whether sessions can be linked across reconnections.
        
        Unlinkability factors:
        - Protocol consistency across sessions
        - Timing patterns
        - Behavioral fingerprinting
        """
        risks = []
        
        # Group connections by peer
        peer_sessions = defaultdict(list)
        for conn in self.collector.connection_history:
            peer_sessions[conn.peer_id].append(conn)
        
        for peer_id, sessions in peer_sessions.items():
            if len(sessions) < 2:
                continue
            
            # Check protocol consistency
            protocol_sets = [set(session.protocols) for session in sessions]
            if len(protocol_sets) > 1:
                # Check if protocols are very similar across sessions
                common_protocols = set.intersection(*protocol_sets) if protocol_sets else set()
                if common_protocols and len(common_protocols) >= 3:
                    risks.append(PrivacyRisk(
                        risk_type="Session Linkability",
                        severity="medium",
                        description=f"Peer {peer_id[:16]}... uses consistent protocol set across sessions",
                        affected_peers=[peer_id],
                        confidence=0.70,
                        recommendations=[
                            "Vary protocol usage across sessions",
                            "Implement protocol randomization",
                            "Use different protocol subsets per session"
                        ]
                    ))
        
        return risks
    
    def _analyze_anonymity_set(self) -> List[PrivacyRisk]:
        """
        Assess the size of the anonymity set.
        
        Larger anonymity set = better privacy
        Small anonymity set = easier to deanonymize
        """
        risks = []
        
        unique_peers = len(self.collector.peers)
        
        if unique_peers < self.MIN_ANONYMITY_SET_SIZE:
            risks.append(PrivacyRisk(
                risk_type="Small Anonymity Set",
                severity="high" if unique_peers < 5 else "medium",
                description=f"Small anonymity set: only {unique_peers} unique peers observed",
                confidence=1.0,
                recommendations=[
                    "Connect to more peers to increase anonymity set",
                    "Use peer discovery mechanisms",
                    "Consider using DHT for larger network participation"
                ]
            ))
        
        return risks
    
    def _analyze_protocol_fingerprinting(self) -> List[PrivacyRisk]:
        """
        Detect if protocol usage patterns can fingerprint the node.
        """
        risks = []
        
        if not self.collector.protocol_usage:
            return risks
        
        # Check for unique or rare protocol combinations
        total_protocols = len(self.collector.protocol_usage)
        if total_protocols > 10:
            risks.append(PrivacyRisk(
                risk_type="Protocol Fingerprinting",
                severity="low",
                description=f"Large number of protocols used ({total_protocols}), may create unique fingerprint",
                confidence=0.50,
                recommendations=[
                    "Limit protocol diversity",
                    "Use common protocol subsets",
                    "Implement protocol usage randomization"
                ]
            ))
        
        return risks
    
    def _analyze_connection_patterns(self) -> List[PrivacyRisk]:
        """
        Analyze connection patterns for privacy leaks.
        """
        risks = []
        
        stats = self.collector.get_statistics()
        
        # Check for imbalanced connection directions
        active_conns = self.collector.get_active_connections()
        if active_conns:
            inbound_count = sum(1 for conn in active_conns if conn.direction == "inbound")
            outbound_count = sum(1 for conn in active_conns if conn.direction == "outbound")
            
            if inbound_count == 0 and outbound_count > 0:
                risks.append(PrivacyRisk(
                    risk_type="Connection Pattern",
                    severity="low",
                    description="Only outbound connections detected, may indicate client-only behavior",
                    confidence=0.60,
                    recommendations=[
                        "Enable inbound connections for better privacy",
                        "Act as relay to blend with network"
                    ]
                ))
        
        return risks
    
    def _analyze_peers(self) -> dict:
        """Perform detailed analysis of peer interactions."""
        peer_analysis = {}
        
        for peer_id, peer_metadata in self.collector.peers.items():
            analysis = {
                "connection_count": peer_metadata.connection_count,
                "total_duration": peer_metadata.total_duration,
                "avg_duration": peer_metadata.total_duration / peer_metadata.connection_count if peer_metadata.connection_count > 0 else 0,
                "multiaddr_diversity": len(peer_metadata.multiaddrs),
                "protocol_count": len(peer_metadata.protocols),
                "linkability_score": self._calculate_peer_linkability(peer_metadata),
            }
            peer_analysis[peer_id] = analysis
        
        return peer_analysis
    
    def _calculate_peer_linkability(self, peer: PeerMetadata) -> float:
        """
        Calculate linkability score for a peer (0.0 = unlinkable, 1.0 = easily linkable).
        """
        score = 0.0
        
        # Factor 1: Multiaddr reuse (fewer unique addresses = more linkable)
        if peer.connection_count > 0:
            addr_diversity = len(peer.multiaddrs) / peer.connection_count
            score += (1.0 - min(addr_diversity, 1.0)) * 0.4
        
        # Factor 2: Protocol consistency (consistent protocols = more linkable)
        if len(peer.protocols) > 0:
            protocol_consistency = min(len(peer.protocols) / 10.0, 1.0)
            score += protocol_consistency * 0.3
        
        # Factor 3: Connection frequency (regular connections = more linkable)
        if peer.connection_count > 5:
            score += 0.3
        
        return min(score, 1.0)
    
    def _analyze_timing_patterns(self) -> dict:
        """Analyze timing patterns in connections."""
        if len(self.collector.connection_times) < 2:
            return {}
        
        intervals = []
        for i in range(1, len(self.collector.connection_times)):
            interval = self.collector.connection_times[i] - self.collector.connection_times[i-1]
            intervals.append(interval)
        
        if not intervals:
            return {}
        
        return {
            "mean_interval": statistics.mean(intervals),
            "median_interval": statistics.median(intervals),
            "stdev_interval": statistics.stdev(intervals) if len(intervals) > 1 else 0,
            "min_interval": min(intervals),
            "max_interval": max(intervals),
            "total_intervals": len(intervals),
        }
    
    def _calculate_overall_risk(self, risks: List[PrivacyRisk]) -> float:
        """
        Calculate overall risk score from individual risks.
        
        Returns:
            Float between 0.0 (no risk) and 1.0 (critical risk)
        """
        if not risks:
            return 0.0
        
        # Weight risks by severity
        severity_weights = {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
        }
        
        weighted_scores = []
        for risk in risks:
            weight = severity_weights.get(risk.severity, 0.5)
            weighted_scores.append(weight * risk.confidence)
        
        # Use max score with some averaging to avoid over-penalization
        if weighted_scores:
            max_score = max(weighted_scores)
            avg_score = sum(weighted_scores) / len(weighted_scores)
            return (max_score * 0.7 + avg_score * 0.3)
        
        return 0.0
    
    def _generate_recommendations(self, risks: List[PrivacyRisk]) -> List[str]:
        """Generate prioritized recommendations based on detected risks."""
        all_recommendations = []
        
        # Collect all recommendations from risks
        for risk in risks:
            all_recommendations.extend(risk.recommendations)
        
        # Count frequency and prioritize
        rec_counter = Counter(all_recommendations)
        
        # Return top recommendations
        return [rec for rec, _ in rec_counter.most_common(10)]

