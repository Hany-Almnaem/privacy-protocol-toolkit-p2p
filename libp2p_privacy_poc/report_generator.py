"""
Report Generator for Privacy Analysis

Generates comprehensive privacy reports in various formats:
- Console output (human-readable)
- JSON (machine-readable)
- HTML (web-viewable)
"""

import json
from typing import Any, Dict, List, Optional

from libp2p_privacy_poc.privacy_analyzer import PrivacyReport, PrivacyRisk
from libp2p_privacy_poc.mock_zk_proofs import MockZKProof
from libp2p_privacy_poc.utils import (
    format_timestamp,
    format_duration,
    truncate_peer_id,
    format_risk_severity,
    color_text,
    generate_report_id,
)


class ReportGenerator:
    """
    Generates privacy analysis reports in multiple formats.
    """
    
    def __init__(self):
        """Initialize the report generator."""
        self.report_id = generate_report_id()
    
    def generate_console_report(
        self,
        report: PrivacyReport,
        zk_proofs: Optional[Dict[str, List[MockZKProof]]] = None,
        verbose: bool = False,
        real_zk_proof: Optional[Dict[str, Any]] = None,
        real_phase2b_proofs: Optional[List[Dict[str, Any]]] = None,
        data_source: Optional[str] = None,
    ) -> str:
        """
        Generate a console-friendly report.
        
        Args:
            report: The privacy report
            zk_proofs: Optional ZK proofs to include
            verbose: Include detailed information
        
        Returns:
            Formatted console report string
        """
        lines = []
        
        # Header
        lines.append("")
        lines.append("=" * 80)
        lines.append(color_text("PRIVACY ANALYSIS REPORT", "cyan"))
        lines.append("=" * 80)
        lines.append(f"Report ID: {self.report_id}")
        lines.append(f"Timestamp: {format_timestamp(report.timestamp)}")
        if data_source:
            lines.append(f"Data Source: {data_source}")
        lines.append("")
        
        # Overall risk score
        risk_color = self._get_risk_color(report.overall_risk_score)
        lines.append(color_text(f"Overall Risk Score: {report.overall_risk_score:.2f}/1.00", risk_color))
        lines.append(color_text(f"Risk Level: {report.get_risk_level()}", risk_color))
        lines.append("")
        
        # Statistics
        lines.append("-" * 80)
        lines.append(color_text("NETWORK STATISTICS", "cyan"))
        lines.append("-" * 80)
        for key, value in report.statistics.items():
            lines.append(f"  {key.replace('_', ' ').title()}: {value}")
        lines.append("")
        
        # Risks summary
        lines.append("-" * 80)
        lines.append(color_text("PRIVACY RISKS DETECTED", "cyan"))
        lines.append("-" * 80)
        lines.append(f"Total Risks: {len(report.risks)}")
        lines.append(f"  {format_risk_severity('critical')}: {len(report.get_critical_risks())}")
        lines.append(f"  {format_risk_severity('high')}: {len(report.get_high_risks())}")
        lines.append(f"  {format_risk_severity('medium')}: {len(report.get_risks_by_severity('medium'))}")
        lines.append(f"  {format_risk_severity('low')}: {len(report.get_risks_by_severity('low'))}")
        lines.append("")
        
        # Detailed risks
        if report.risks:
            lines.append("-" * 80)
            lines.append(color_text("DETAILED RISK ANALYSIS", "cyan"))
            lines.append("-" * 80)
            
            for i, risk in enumerate(report.risks, 1):
                lines.append(f"\n{i}. {format_risk_severity(risk.severity)} - {risk.risk_type}")
                lines.append(f"   {risk.description}")
                lines.append(f"   Confidence: {risk.confidence:.0%}")
                
                if verbose and risk.affected_peers:
                    lines.append(f"   Affected Peers: {len(risk.affected_peers)}")
                    for peer in risk.affected_peers[:3]:
                        lines.append(f"     - {truncate_peer_id(peer)}")
                
                if verbose and risk.recommendations:
                    lines.append("   Recommendations:")
                    for rec in risk.recommendations[:2]:
                        lines.append(f"     • {rec}")
        
        # ZK Proofs section
        if zk_proofs:
            lines.append("")
            lines.append("-" * 80)
            lines.append(color_text("ZERO-KNOWLEDGE PROOFS", "cyan"))
            lines.append(color_text("⚠️  MOCK PROOFS - FOR DEMONSTRATION ONLY", "yellow"))
            lines.append("-" * 80)
            
            total_proofs = sum(len(proofs) for proofs in zk_proofs.values())
            lines.append(f"Total ZK Proofs Generated: {total_proofs}")
            
            for proof_type, proofs in zk_proofs.items():
                if proofs:
                    lines.append(f"\n{proof_type.replace('_', ' ').title()}: {len(proofs)}")
                    if verbose:
                        for proof in proofs[:3]:
                            lines.append(f"  • {proof.claim}")
                            lines.append(f"    Verified: {color_text('✓', 'green') if proof.verify() else color_text('✗', 'red')}")
        
        if real_zk_proof is not None or real_phase2b_proofs:
            lines.append("")
            lines.append("-" * 80)
            lines.append(color_text("REAL ZK PROOFS (EXPERIMENTAL)", "cyan"))
            lines.append("-" * 80)
            if real_zk_proof is not None:
                lines.append(f"Backend: {real_zk_proof.get('backend', 'unknown')}")
                lines.append(f"Statement: {real_zk_proof.get('statement', 'unknown')}")
                peer_id = real_zk_proof.get("peer_id")
                session_id = real_zk_proof.get("session_id")
                if peer_id:
                    lines.append(f"Peer ID: {truncate_peer_id(peer_id)}")
                if session_id:
                    lines.append(f"Session ID: {session_id}")
                if real_zk_proof.get("verified"):
                    lines.append(f"Verified: {color_text('✓', 'green')}")
                else:
                    lines.append(f"Verified: {color_text('✗', 'red')}")
                    error = real_zk_proof.get("error")
                    if error:
                        lines.append(f"Error: {error}")

            if real_phase2b_proofs:
                if real_zk_proof is not None:
                    lines.append("")
                lines.append("Phase 2B Statements:")
                for proof in real_phase2b_proofs:
                    statement = proof.get("statement", "unknown")
                    verified = proof.get("verified")
                    status = color_text("✓", "green") if verified else color_text("✗", "red")
                    lines.append(f"  - {statement}: {status}")
                    error = proof.get("error")
                    if not verified and error:
                        lines.append(f"    Error: {error}")

        # Recommendations
        if report.recommendations:
            lines.append("")
            lines.append("-" * 80)
            lines.append(color_text("RECOMMENDATIONS", "cyan"))
            lines.append("-" * 80)
            for i, rec in enumerate(report.recommendations[:10], 1):
                lines.append(f"{i}. {rec}")
        
        # Timing analysis
        if verbose and report.timing_analysis:
            lines.append("")
            lines.append("-" * 80)
            lines.append(color_text("TIMING ANALYSIS", "cyan"))
            lines.append("-" * 80)
            for key, value in report.timing_analysis.items():
                if isinstance(value, float):
                    lines.append(f"  {key.replace('_', ' ').title()}: {format_duration(value)}")
                else:
                    lines.append(f"  {key.replace('_', ' ').title()}: {value}")
        
        # Footer
        lines.append("")
        lines.append("=" * 80)
        lines.append(color_text("END OF REPORT", "cyan"))
        lines.append("=" * 80)
        lines.append("")
        
        return "\n".join(lines)
    
    def generate_json_report(
        self,
        report: PrivacyReport,
        zk_proofs: Optional[Dict[str, List[MockZKProof]]] = None,
        certificate: Optional[dict] = None,
        real_zk_proof: Optional[Dict[str, Any]] = None,
        real_phase2b_proofs: Optional[List[Dict[str, Any]]] = None,
        data_source: Optional[str] = None,
    ) -> str:
        """
        Generate a JSON report.
        
        Args:
            report: The privacy report
            zk_proofs: Optional ZK proofs to include
            certificate: Optional privacy certificate
        
        Returns:
            JSON string
        """
        data = {
            "report_id": self.report_id,
            "timestamp": report.timestamp,
            "privacy_report": report.to_dict(),
        }
        if data_source:
            data["data_source"] = data_source
        
        if zk_proofs:
            data["zk_proofs"] = {
                proof_type: [p.to_dict() for p in proofs]
                for proof_type, proofs in zk_proofs.items()
            }

        if real_zk_proof is not None:
            data["real_zk_proofs"] = [real_zk_proof]

        if real_phase2b_proofs:
            data["real_phase2b_proofs"] = real_phase2b_proofs
        
        if certificate:
            data["privacy_certificate"] = certificate
        
        data["metadata"] = {
            "version": "0.1.0",
            "generator": "libp2p-privacy-poc",
            "WARNING": "PROOF OF CONCEPT - NOT PRODUCTION READY",
        }
        
        return json.dumps(data, indent=2)
    
    def generate_html_report(
        self,
        report: PrivacyReport,
        zk_proofs: Optional[Dict[str, List[MockZKProof]]] = None,
        real_zk_proof: Optional[Dict[str, Any]] = None,
        real_phase2b_proofs: Optional[List[Dict[str, Any]]] = None,
        data_source: Optional[str] = None,
    ) -> str:
        """
        Generate an HTML report.
        
        Args:
            report: The privacy report
            zk_proofs: Optional ZK proofs to include
        
        Returns:
            HTML string
        """
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Privacy Analysis Report - {self.report_id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .risk-score {{
            font-size: 48px;
            font-weight: bold;
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .risk-low {{ background-color: #4CAF50; color: white; }}
        .risk-medium {{ background-color: #FF9800; color: white; }}
        .risk-high {{ background-color: #F44336; color: white; }}
        .risk-critical {{ background-color: #D32F2F; color: white; }}
        .risk-item {{
            margin: 15px 0;
            padding: 15px;
            border-left: 4px solid #ccc;
            background-color: #f9f9f9;
        }}
        .risk-item.critical {{ border-left-color: #D32F2F; }}
        .risk-item.high {{ border-left-color: #F44336; }}
        .risk-item.medium {{ border-left-color: #FF9800; }}
        .risk-item.low {{ border-left-color: #4CAF50; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .badge-critical {{ background-color: #D32F2F; }}
        .badge-high {{ background-color: #F44336; }}
        .badge-medium {{ background-color: #FF9800; }}
        .badge-low {{ background-color: #4CAF50; }}
        .warning {{
            background-color: #FFF3CD;
            border: 1px solid #FFC107;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            padding: 15px;
            background-color: #f0f0f0;
            border-radius: 4px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }}
        .stat-label {{
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Privacy Analysis Report</h1>
        <p><strong>Report ID:</strong> {self.report_id}</p>
        <p><strong>Generated:</strong> {format_timestamp(report.timestamp)}</p>
        {f"<p><strong>Data Source:</strong> {data_source}</p>" if data_source else ""}
        
        <div class="warning">
            <strong>⚠️ PROOF OF CONCEPT</strong><br>
            This report is generated by a proof-of-concept tool. ZK proofs are mock implementations for demonstration only.
        </div>
        
        <h2>Overall Risk Assessment</h2>
        <div class="risk-score {self._get_risk_class(report.overall_risk_score)}">
            {report.overall_risk_score:.2f}/1.00<br>
            <span style="font-size: 24px;">{report.get_risk_level()}</span>
        </div>
        
        <h2>Network Statistics</h2>
        <div class="stats">
            {self._generate_stat_cards(report.statistics)}
        </div>
        
        <h2>Privacy Risks ({len(report.risks)})</h2>
        {self._generate_risk_items_html(report.risks)}
        
        {self._generate_zk_proofs_html(zk_proofs) if zk_proofs else ''}
        
        {self._generate_real_zk_proof_html(real_zk_proof, real_phase2b_proofs)}
        
        <h2>Recommendations</h2>
        <ol>
            {self._generate_recommendations_html(report.recommendations)}
        </ol>
    </div>
</body>
</html>
"""
        return html
    
    def _get_risk_color(self, score: float) -> str:
        """Get color for risk score."""
        if score >= 0.75:
            return "red"
        elif score >= 0.5:
            return "yellow"
        elif score >= 0.25:
            return "yellow"
        else:
            return "green"
    
    def _get_risk_class(self, score: float) -> str:
        """Get CSS class for risk score."""
        if score >= 0.75:
            return "risk-critical"
        elif score >= 0.5:
            return "risk-high"
        elif score >= 0.25:
            return "risk-medium"
        else:
            return "risk-low"
    
    def _generate_stat_cards(self, statistics: dict) -> str:
        """Generate HTML for statistics cards."""
        cards = []
        for key, value in statistics.items():
            label = key.replace('_', ' ').title()
            cards.append(f"""
            <div class="stat-card">
                <div class="stat-value">{value}</div>
                <div class="stat-label">{label}</div>
            </div>
            """)
        return "\n".join(cards)
    
    def _generate_risk_items_html(self, risks: List[PrivacyRisk]) -> str:
        """Generate HTML for risk items."""
        if not risks:
            return "<p>No privacy risks detected.</p>"
        
        items = []
        for risk in risks:
            items.append(f"""
            <div class="risk-item {risk.severity}">
                <span class="badge badge-{risk.severity}">{risk.severity.upper()}</span>
                <strong>{risk.risk_type}</strong>
                <p>{risk.description}</p>
                <small>Confidence: {risk.confidence:.0%}</small>
            </div>
            """)
        return "\n".join(items)
    
    def _generate_zk_proofs_html(self, zk_proofs: Dict[str, List[MockZKProof]]) -> str:
        """Generate HTML for ZK proofs section."""
        total_proofs = sum(len(proofs) for proofs in zk_proofs.values())
        
        html = f"""
        <h2>Zero-Knowledge Proofs ({total_proofs})</h2>
        <div class="warning">
            <strong>⚠️ MOCK PROOFS</strong><br>
            These are demonstration proofs only. Real cryptographic implementation required for production.
        </div>
        """
        
        for proof_type, proofs in zk_proofs.items():
            if proofs:
                html += f"<h3>{proof_type.replace('_', ' ').title()} ({len(proofs)})</h3><ul>"
                for proof in proofs[:5]:
                    verified = "✓" if proof.verify() else "✗"
                    html += f"<li>{proof.claim} {verified}</li>"
                html += "</ul>"
        
        return html

    def _generate_real_zk_proof_html(
        self,
        real_zk_proof: Optional[Dict[str, Any]],
        real_phase2b_proofs: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Generate HTML for real ZK proof section."""
        if real_zk_proof is None and not real_phase2b_proofs:
            return ""

        proof_items = ""
        if real_zk_proof is not None:
            verified = "✓" if real_zk_proof.get("verified") else "✗"
            error = real_zk_proof.get("error")
            error_html = f"<p><strong>Error:</strong> {error}</p>" if error else ""
            proof_items = f"""
            <h3>Commitment Opening Proof</h3>
            <ul>
                <li><strong>Backend:</strong> {real_zk_proof.get('backend', 'unknown')}</li>
                <li><strong>Statement:</strong> {real_zk_proof.get('statement', 'unknown')}</li>
                <li><strong>Peer ID:</strong> {real_zk_proof.get('peer_id', '')}</li>
                <li><strong>Session ID:</strong> {real_zk_proof.get('session_id', '')}</li>
                <li><strong>Verified:</strong> {verified}</li>
            </ul>
            {error_html}
            """

        phase2b_items = ""
        if real_phase2b_proofs:
            rows = []
            for proof in real_phase2b_proofs:
                statement = proof.get("statement", "unknown")
                verified = "✓" if proof.get("verified") else "✗"
                error = proof.get("error")
                error_html = f" <span>(Error: {error})</span>" if error and not proof.get("verified") else ""
                rows.append(f"<li><strong>{statement}:</strong> {verified}{error_html}</li>")
            phase2b_items = f"""
            <h3>Phase 2B Statements</h3>
            <ul>
                {''.join(rows)}
            </ul>
            """

        return f"""
        <h2>Real ZK Proofs (Experimental)</h2>
        <div class="warning">
            <strong>Experimental</strong><br>
            This section contains real Phase 2A and Phase 2B proofs.
        </div>
        {proof_items}
        {phase2b_items}
        """
    
    def _generate_recommendations_html(self, recommendations: List[str]) -> str:
        """Generate HTML for recommendations."""
        if not recommendations:
            return "<li>No specific recommendations at this time.</li>"
        
        return "\n".join(f"<li>{rec}</li>" for rec in recommendations[:10])
