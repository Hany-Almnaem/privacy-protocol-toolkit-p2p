"""
Command-Line Interface for libp2p Privacy Analysis Tool

Provides easy-to-use commands for privacy analysis, reporting, and demonstrations.
"""

import click
import json
import sys
import time
from pathlib import Path
from typing import Optional

from libp2p import new_host
from multiaddr import Multiaddr

from libp2p_privacy_poc import print_disclaimer
from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer
from libp2p_privacy_poc.mock_zk_proofs import MockZKProofSystem
from libp2p_privacy_poc.report_generator import ReportGenerator
from libp2p_privacy_poc.zk_integration import (
    ZKDataPreparator,
    generate_real_commitment_proof,
)


@click.group()
@click.version_option(version="0.1.0")
def main():
    """
    libp2p Privacy Analysis Tool - Proof of Concept
    
    A privacy analysis tool for py-libp2p that detects privacy leaks and
    demonstrates zero-knowledge proof concepts.
    
    ⚠️  PROOF OF CONCEPT - NOT PRODUCTION READY
    """
    pass


@main.command()
@click.option(
    '--format',
    type=click.Choice(['console', 'json', 'html'], case_sensitive=False),
    default='console',
    help='Output format for the report'
)
@click.option(
    '--output',
    type=click.Path(),
    help='Output file path (default: stdout for console, privacy_report.{format} for others)'
)
@click.option(
    '--with-zk-proofs',
    is_flag=True,
    help='Include mock ZK proofs in the report'
)
@click.option(
    '--with-real-zk',
    is_flag=True,
    help='Include real Pedersen+Schnorr proof (experimental)'
)
@click.option(
    '--duration',
    type=int,
    default=10,
    help='Analysis duration in seconds (default: 10)'
)
@click.option(
    '--listen-addr',
    type=str,
    default='/ip4/127.0.0.1/tcp/0',
    help='Listen address for the node (default: /ip4/127.0.0.1/tcp/0)'
)
@click.option(
    '--connect-to',
    type=str,
    help='Peer multiaddr to connect to (optional)'
)
@click.option(
    '--simulate',
    is_flag=True,
    default=False,
    help='Use simulated data instead of real network (default: False)'
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Enable verbose output'
)
def analyze(
    format,
    output,
    with_zk_proofs,
    with_real_zk,
    duration,
    listen_addr,
    connect_to,
    simulate,
    verbose
):
    """
    Run privacy analysis on libp2p node.
    
    By default, uses REAL py-libp2p connections. Use --simulate for fast testing.
    
    Examples:
    
        # Basic real network analysis (10 seconds)
        libp2p-privacy analyze
        
        # Analyze for 30 seconds
        libp2p-privacy analyze --duration 30
        
        # Connect to specific peer
        libp2p-privacy analyze --connect-to /ip4/127.0.0.1/tcp/4001/p2p/QmPeerID...
        
        # Generate JSON report
        libp2p-privacy analyze --format json --output report.json
        
        # Fast simulation (for CI/testing)
        libp2p-privacy analyze --simulate
    """
    import trio
    
    async def _analyze_real_network():
        """Run analysis on real py-libp2p network."""
        from libp2p import new_host
        from libp2p.peer.peerinfo import info_from_p2p_addr
        from libp2p.tools.async_service import background_trio_service
        from libp2p_privacy_poc.utils import get_peer_listening_address
        
        click.echo("\n" + "=" * 70)
        click.echo(click.style("libp2p Privacy Analysis Tool", fg="cyan", bold=True))
        click.echo("=" * 70)
        click.echo(click.style("\n✓ Using REAL py-libp2p network", fg="green"))
        
        # Create host
        if verbose:
            click.echo(f"\nCreating host...")
        host = new_host()
        click.echo(f"Host ID: {host.get_id()}")
        
        # Create collector
        collector = MetadataCollector(host)
        if verbose:
            click.echo("✓ MetadataCollector attached (auto-capturing events)")
        
        # Start network
        if verbose:
            click.echo(f"\nStarting network on {listen_addr}...")
        
        network = host.get_network()
        
        async with background_trio_service(network):
            # Start listener with timeout
            try:
                with trio.fail_after(5):
                    await network.listen(Multiaddr(listen_addr))
            except trio.TooSlowError:
                click.echo(click.style("✗ Timeout starting listener", fg="red"), err=True)
                return None, None
            
            await trio.sleep(0.5)
            
            # Get actual listening address
            try:
                actual_addr = get_peer_listening_address(host)
                click.echo(f"✓ Listening on: {actual_addr}")
            except ValueError as e:
                click.echo(click.style(f"✗ {e}", fg="red"), err=True)
                return None, None
            
            # Connect to peer if specified
            if connect_to:
                if verbose:
                    click.echo(f"\nConnecting to peer: {connect_to}")
                try:
                    peer_info = info_from_p2p_addr(Multiaddr(connect_to))
                    with trio.fail_after(10):
                        await host.connect(peer_info)
                    click.echo(click.style("✓ Connected successfully", fg="green"))
                except Exception as e:
                    click.echo(click.style(f"⚠️  Connection failed: {e}", fg="yellow"))
                    click.echo("Continuing with analysis of local activity...")
            
            # Capture events for specified duration
            click.echo(f"\nCapturing network events for {duration} seconds...")
            if verbose:
                # Show progress
                for i in range(duration):
                    stats = collector.get_statistics()
                    click.echo(f"  {i+1}s: {stats['total_connections']} connections, {stats['unique_peers']} peers", nl=False)
                    click.echo("\r", nl=False)
                    await trio.sleep(1)
                click.echo()  # New line
            else:
                await trio.sleep(duration)
            
            # Get final statistics
            stats = collector.get_statistics()
            click.echo(f"\n{click.style('✓ Capture Complete!', fg='green')}")
            click.echo(f"  Connections: {stats['total_connections']}")
            click.echo(f"  Unique Peers: {stats['unique_peers']}")
            click.echo(f"  Protocols: {stats['protocols_used']}")
            
            # Cleanup
            if verbose:
                click.echo("\nClosing network...")
            with trio.fail_after(5):
                await host.close()
            
            return collector, stats
    
    def _analyze_simulated():
        """Run analysis with simulated data."""
        click.echo("\n" + "=" * 70)
        click.echo(click.style("libp2p Privacy Analysis Tool", fg="cyan", bold=True))
        click.echo("=" * 70)
        click.echo(click.style("\n⚠️  Using simulated data for demonstration", fg="yellow"))
        
        if verbose:
            click.echo("Creating MetadataCollector...")
        collector = MetadataCollector(libp2p_host=None)
        
        if verbose:
            click.echo("Simulating network activity...")
        _simulate_network_activity(collector, verbose)
        
        stats = collector.get_statistics()
        return collector, stats
    
    try:
        # Run analysis (real or simulated)
        if simulate:
            collector, stats = _analyze_simulated()
        else:
            collector, stats = trio.run(_analyze_real_network)
            
        if collector is None:
            click.echo(click.style("\n✗ Analysis failed", fg="red"), err=True)
            sys.exit(1)
        
        # Run privacy analysis
        if verbose:
            click.echo("\nRunning privacy analysis...")
        analyzer = PrivacyAnalyzer(collector)
        report = analyzer.analyze()
        
        click.echo(f"\n{click.style('✓ Analysis Complete!', fg='green')}")
        click.echo(f"  Risk Score: {report.overall_risk_score:.2f}/1.00")
        click.echo(f"  Risks Detected: {len(report.risks)}")
        
        # Generate ZK proofs if requested
        zk_proofs = None
        real_zk_proof = None
        if with_zk_proofs:
            if verbose:
                click.echo("\nGenerating mock ZK proofs...")
            zk_proofs = _generate_zk_proofs(collector, verbose)
            click.echo(click.style(f"✓ Generated {sum(len(v) for v in zk_proofs.values())} ZK proofs", fg="green"))

        if with_real_zk:
            if verbose:
                click.echo("\nGenerating real ZK proof (Pedersen+Schnorr)...")
            real_zk_proof = generate_real_commitment_proof(collector)
            if real_zk_proof.get("verified"):
                click.echo(click.style("✓ Real ZK proof verified", fg="green"))
            else:
                error = real_zk_proof.get("error") or "unavailable"
                click.echo(
                    click.style(
                        f"⚠️  Real ZK proof unavailable: {error}",
                        fg="yellow",
                    )
                )
        
        # Generate report
        if verbose:
            click.echo(f"\nGenerating {format} report...")
        
        report_gen = ReportGenerator()
        
        if format == 'console':
            report_content = report_gen.generate_console_report(
                report,
                zk_proofs,
                verbose=verbose,
                real_zk_proof=real_zk_proof,
            )
            if output:
                Path(output).write_text(report_content)
                click.echo(f"\n{click.style(f'✓ Report saved to: {output}', fg='green')}")
            else:
                click.echo("\n" + report_content)
        
        elif format == 'json':
            report_content = report_gen.generate_json_report(
                report,
                zk_proofs,
                real_zk_proof=real_zk_proof,
            )
            output_path = output or "privacy_report.json"
            Path(output_path).write_text(report_content)
            click.echo(f"\n{click.style(f'✓ JSON report saved to: {output_path}', fg='green')}")
            
        elif format == 'html':
            report_content = report_gen.generate_html_report(
                report,
                zk_proofs,
                real_zk_proof=real_zk_proof,
            )
            output_path = output or "privacy_report.html"
            Path(output_path).write_text(report_content)
            click.echo(f"\n{click.style(f'✓ HTML report saved to: {output_path}', fg='green')}")
        
        click.echo("\n" + "=" * 70)
        
    except Exception as e:
        click.echo(click.style(f"\n✗ Error: {e}", fg="red"), err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option(
    '--verbose',
    is_flag=True,
    help='Enable verbose output'
)
def demo(verbose):
    """
    Run demonstration scenarios showing privacy analysis capabilities with REAL connections.
    
    Runs all 5 demo scenarios from examples/demo_scenarios.py using real py-libp2p networks.
    Demonstrates timing correlation, anonymity sets, protocol fingerprinting, and ZK proofs.
    
    Examples:
    
        # Run all demonstrations with real networks
        libp2p-privacy demo
        
        # Run with verbose output
        libp2p-privacy demo --verbose
    
    Note: This command runs the full demo_scenarios.py script which may take 1-2 minutes.
    """
    import trio
    import subprocess
    
    try:
        click.echo("\n" + "=" * 70)
        click.echo(click.style("Privacy Analysis Demonstrations", fg="cyan", bold=True))
        click.echo("=" * 70)
        click.echo(click.style("\n✓ Running REAL network demonstrations", fg="green"))
        click.echo("This will run all 5 scenarios with real py-libp2p connections.\n")
        
        # Run the demo_scenarios.py script
        import os
        examples_dir = os.path.join(os.path.dirname(__file__), '..', 'examples')
        demo_script = os.path.join(examples_dir, 'demo_scenarios.py')
        
        if not os.path.exists(demo_script):
            click.echo(click.style(f"✗ Demo script not found: {demo_script}", fg="red"), err=True)
            sys.exit(1)
        
        # Run the script
        result = subprocess.run(
            [sys.executable, demo_script],
            cwd=os.path.dirname(demo_script),
            capture_output=False if verbose else True
        )
        
        if result.returncode == 0:
            click.echo("\n" + "=" * 70)
            click.echo(click.style("✓ All Demonstrations Complete!", fg="green"))
            click.echo("=" * 70 + "\n")
        else:
            click.echo(click.style(f"\n✗ Demo failed with exit code {result.returncode}", fg="red"), err=True)
            sys.exit(result.returncode)
        
    except Exception as e:
        click.echo(click.style(f"\n✗ Error: {e}", fg="red"), err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
def version():
    """Show version and disclaimer information."""
    click.echo("\nlibp2p Privacy Analysis Tool v0.1.0")
    click.echo("Proof of Concept - Not Production Ready\n")
    print_disclaimer()


def _simulate_network_activity(collector: MetadataCollector, verbose: bool = False):
    """Simulate network activity for demonstration."""
    peers = [
        ("QmPeer1abc123def456", "/ip4/192.168.1.100/tcp/4001"),
        ("QmPeer2xyz789ghi012", "/ip4/192.168.1.101/tcp/4001"),
        ("QmPeer3jkl345mno678", "/ip4/192.168.1.102/tcp/4001"),
        ("QmPeer1abc123def456", "/ip4/192.168.1.100/tcp/4002"),
        ("QmPeer4pqr901stu234", "/ip4/192.168.1.103/tcp/4001"),
    ]
    
    for i, (peer_id_str, addr_str) in enumerate(peers):
        collector.on_connection_opened(
            peer_id=peer_id_str,
            multiaddr=Multiaddr(addr_str),
            direction="outbound" if i % 2 == 0 else "inbound"
        )
        time.sleep(0.05)
    
    # Simulate protocol negotiations
    collector.on_protocol_negotiated("QmPeer1abc123def456", "/ipfs/id/1.0.0")
    collector.on_protocol_negotiated("QmPeer1abc123def456", "/ipfs/bitswap/1.2.0")
    
    # Simulate stream activity
    collector.on_stream_opened("QmPeer1abc123def456")
    collector.on_stream_opened("QmPeer2xyz789ghi012")


def _generate_zk_proofs(collector: MetadataCollector, verbose: bool = False):
    """Generate mock ZK proofs for demonstration."""
    zk_system = MockZKProofSystem()
    zk_proofs = {}
    
    peer_ids = list(collector.peers.keys())
    if peer_ids:
        # Anonymity set proof
        anonymity_proof = zk_system.generate_anonymity_set_proof(
            peer_id=peer_ids[0],
            anonymity_set_size=len(peer_ids)
        )
        zk_proofs["anonymity_set"] = [anonymity_proof]
        
        # Unlinkability proof (if multiple peers)
        if len(peer_ids) >= 2:
            unlinkability_proof = zk_system.generate_unlinkability_proof(
                session_1_id=peer_ids[0],
                session_2_id=peer_ids[1]
            )
            zk_proofs["unlinkability"] = [unlinkability_proof]
    
    return zk_proofs


def _demo_timing_correlation(verbose: bool):
    """Demonstrate timing correlation detection."""
    click.echo("\n" + "-" * 70)
    click.echo(click.style("Demo: Timing Correlation Detection", fg="cyan", bold=True))
    click.echo("-" * 70)
    click.echo("\nThis demo shows how timing patterns can leak privacy information.")
    
    collector = MetadataCollector()
    
    # Create regular timing pattern
    for i in range(5):
        collector.on_connection_opened(
            peer_id=f"QmPeer{i}",
            multiaddr=Multiaddr("/ip4/127.0.0.1/tcp/4001"),
            direction="outbound"
        )
        time.sleep(0.1)  # Regular interval
    
    analyzer = PrivacyAnalyzer(collector)
    report = analyzer.analyze()
    
    timing_risks = [r for r in report.risks if r.risk_type == "Timing Correlation"]
    click.echo(f"\n{click.style(f'✓ Detected {len(timing_risks)} timing-related risks', fg='yellow')}")
    
    for risk in timing_risks:
        click.echo(f"  • {risk.description}")


def _demo_peer_linkability(verbose: bool):
    """Demonstrate peer linkability detection."""
    click.echo("\n" + "-" * 70)
    click.echo(click.style("Demo: Peer Linkability Detection", fg="cyan", bold=True))
    click.echo("-" * 70)
    click.echo("\nThis demo shows how multiple connections can be linked to the same peer.")
    
    collector = MetadataCollector()
    
    # Same peer, multiple addresses
    peer_id = "QmTestPeer123"
    for i in range(3):
        collector.on_connection_opened(
            peer_id=peer_id,
            multiaddr=Multiaddr(f"/ip4/192.168.1.100/tcp/{4001+i}"),
            direction="outbound"
        )
    
    analyzer = PrivacyAnalyzer(collector)
    report = analyzer.analyze()
    
    click.echo(f"\n{click.style('✓ Analysis complete', fg='yellow')}")
    click.echo(f"  • Detected connections from same peer across {len(collector.peers[peer_id].multiaddrs)} addresses")


def _demo_anonymity_set(verbose: bool):
    """Demonstrate anonymity set analysis."""
    click.echo("\n" + "-" * 70)
    click.echo(click.style("Demo: Anonymity Set Analysis with ZK Proofs", fg="cyan", bold=True))
    click.echo("-" * 70)
    click.echo("\nThis demo shows anonymity set analysis and ZK proof generation.")
    
    collector = MetadataCollector()
    
    # Simulate connections to various peers
    for i in range(10):
        collector.on_connection_opened(
            peer_id=f"QmPeer{i}",
            multiaddr=Multiaddr(f"/ip4/192.168.1.{100+i}/tcp/4001"),
            direction="outbound"
        )
    
    analyzer = PrivacyAnalyzer(collector)
    report = analyzer.analyze()
    
    # Generate ZK proof
    zk_system = MockZKProofSystem()
    peer_ids = list(collector.peers.keys())
    proof = zk_system.generate_anonymity_set_proof(
        peer_id=peer_ids[0],
        anonymity_set_size=len(peer_ids)
    )
    
    click.echo(f"\n{click.style('✓ Anonymity analysis complete', fg='yellow')}")
    click.echo(f"  • Anonymity set size: {len(peer_ids)}")
    click.echo(f"  • Generated ZK proof: {proof.proof_type}")
    click.echo(f"  • Proof verified: {click.style('✓', fg='green') if zk_system.verify_proof(proof) else click.style('✗', fg='red')}")


if __name__ == "__main__":
    main()
