"""
Command-Line Interface for libp2p Privacy Analysis Tool

Provides easy-to-use commands for privacy analysis, reporting, and demonstrations.
"""

import click
import json
import logging
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
    generate_real_phase2b_proofs,
    generate_snark_phase2b_proofs,
)


@click.group()
@click.version_option(version="0.1.0")
@click.option(
    "--log-level",
    type=click.Choice(
        ["debug", "info", "warning", "error", "critical"],
        case_sensitive=False,
    ),
    default="warning",
    show_default=True,
    help="Logging verbosity",
)
def main(log_level):
    """
    libp2p Privacy Analysis Tool - Proof of Concept
    
    A privacy analysis tool for py-libp2p that detects privacy leaks and
    demonstrates zero-knowledge proof concepts.
    
    ⚠️  PROOF OF CONCEPT - NOT PRODUCTION READY
    """
    _configure_logging(log_level)


def _configure_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper(), logging.WARNING)
    logging.basicConfig(level=numeric_level, force=True)


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
    '--with-real-phase2b',
    is_flag=True,
    help='Include real proof statements (experimental)'
)
@click.option(
    '--zk-backend',
    type=click.Choice(
        ['mock', 'pedersen', 'snark-membership', 'snark'], case_sensitive=False
    ),
    default=None,
    help=(
        'Select ZK backend for proof statements '
        '(mock, pedersen, snark-membership)'
    )
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
    '--offline/--no-network',
    is_flag=True,
    default=False,
    help='Disable network proof exchange'
)
@click.option(
    '--zk-peer',
    type=str,
    help='Peer ID or multiaddr for network proof exchange'
)
@click.option(
    '--zk-statement',
    type=click.Choice(['membership', 'continuity', 'unlinkability'], case_sensitive=False),
    default='membership',
    show_default=True,
    help='Statement to request over network'
)
@click.option(
    '--zk-timeout',
    type=int,
    default=8,
    show_default=True,
    help='Network proof exchange timeout in seconds'
)
@click.option(
    '--zk-assets-dir',
    type=click.Path(),
    default='privacy_circuits/params',
    show_default=True,
    help='Base directory for network proof verifier assets'
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
    with_real_phase2b,
    zk_backend,
    duration,
    listen_addr,
    connect_to,
    simulate,
    offline,
    zk_peer,
    zk_statement,
    zk_timeout,
    zk_assets_dir,
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
        with_snark_phase2b = False
        if zk_backend:
            zk_backend = zk_backend.lower()
            if zk_backend == "mock":
                with_zk_proofs = True
            elif zk_backend == "pedersen":
                with_real_phase2b = True
            elif zk_backend in ("snark-membership", "snark"):
                with_snark_phase2b = True

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
        real_phase2b_proofs = None
        snark_phase2b_proofs = None
        network_snark_proofs = None
        if not simulate and not offline:
            try:
                from libp2p_privacy_poc.network.privacyzk.integration import (
                    try_real_proofs,
                )
                exchange = try_real_proofs(
                    collector,
                    statement=zk_statement,
                    assets_dir=zk_assets_dir,
                    timeout=zk_timeout,
                    zk_peer=zk_peer,
                    offline=offline,
                    require_real=True,
                )
                if exchange.attempted:
                    network_snark_proofs = exchange.results
                    if exchange.success:
                        click.echo(
                            click.style(
                                "✓ Real ZK proof exchange verified",
                                fg="green",
                            )
                        )
                    else:
                        click.echo(
                            click.style(
                                "⚠️  Real ZK proof exchange unavailable; falling back to legacy simulation.",
                                fg="yellow",
                            )
                        )
            except Exception as exc:
                network_snark_proofs = [
                    {
                        "backend": "snark-network",
                        "statement": f"{zk_statement}_v2",
                        "peer_id": None,
                        "schema_v": 2,
                        "depth": 16 if zk_statement == "membership" else 0,
                        "verified": False,
                        "error": str(exc),
                    }
                ]
                click.echo(
                    click.style(
                        "⚠️  Real ZK proof exchange unavailable; falling back to legacy simulation.",
                        fg="yellow",
                    )
                )
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

        if with_real_phase2b:
            if verbose:
                click.echo("\nGenerating real proof statements...")
            real_phase2b_proofs = generate_real_phase2b_proofs(collector)
            verified_count = sum(
                1 for item in real_phase2b_proofs if item.get("verified")
            )
            if verified_count:
                click.echo(
                    click.style(
                        f"✓ Real proof statements verified: {verified_count}/{len(real_phase2b_proofs)}",
                        fg="green",
                    )
                )
            else:
                click.echo(
                    click.style(
                        "⚠️  Real proof statements unavailable",
                        fg="yellow",
                    )
                )

        if with_snark_phase2b:
            if verbose:
                click.echo("\nGenerating SNARK proof statement...")
            try:
                snark_phase2b_proofs = generate_snark_phase2b_proofs(collector)
            except Exception as exc:
                click.echo(
                    click.style(
                        f"⚠️  SNARK proof statements unavailable: {exc}",
                        fg="yellow",
                    )
                )
                if zk_proofs is None:
                    zk_proofs = _generate_zk_proofs(collector, verbose)
            else:
                verified_count = sum(
                    1 for item in snark_phase2b_proofs if item.get("verified")
                )
                if verified_count:
                    click.echo(
                        click.style(
                            f"✓ SNARK proof statements verified: {verified_count}/{len(snark_phase2b_proofs)}",
                            fg="green",
                        )
                    )
                else:
                    click.echo(
                        click.style(
                            "⚠️  SNARK proof statements unavailable; falling back to mock proofs",
                            fg="yellow",
                        )
                    )
                    if zk_proofs is None:
                        zk_proofs = _generate_zk_proofs(collector, verbose)

        if network_snark_proofs:
            if snark_phase2b_proofs:
                snark_phase2b_proofs = network_snark_proofs + snark_phase2b_proofs
            else:
                snark_phase2b_proofs = network_snark_proofs
        
        # Generate report
        if verbose:
            click.echo(f"\nGenerating {format} report...")
        
        report_gen = ReportGenerator()
        data_source = "SIMULATED" if simulate else "REAL"
        
        if format == 'console':
            report_content = report_gen.generate_console_report(
                report,
                zk_proofs,
                verbose=verbose,
                real_zk_proof=real_zk_proof,
                real_phase2b_proofs=real_phase2b_proofs,
                snark_phase2b_proofs=snark_phase2b_proofs,
                data_source=data_source,
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
                real_phase2b_proofs=real_phase2b_proofs,
                snark_phase2b_proofs=snark_phase2b_proofs,
                data_source=data_source,
            )
            output_path = output or "privacy_report.json"
            Path(output_path).write_text(report_content)
            click.echo(f"\n{click.style(f'✓ JSON report saved to: {output_path}', fg='green')}")
            
        elif format == 'html':
            report_content = report_gen.generate_html_report(
                report,
                zk_proofs,
                real_zk_proof=real_zk_proof,
                real_phase2b_proofs=real_phase2b_proofs,
                snark_phase2b_proofs=snark_phase2b_proofs,
                data_source=data_source,
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


@main.command(name="zk-serve")
@click.option(
    "--listen-addr",
    type=str,
    default=None,
    help="Listen address (default: /ip4/<host>/tcp/<port>)",
)
@click.option(
    "--host",
    type=str,
    default="127.0.0.1",
    help="Listen host (default: 127.0.0.1)",
)
@click.option(
    "--port",
    type=int,
    default=0,
    help="Listen port (default: 0)",
)
@click.option(
    "--prove-mode",
    type=click.Choice(["fixture", "real", "prefer-real"], case_sensitive=False),
    default="fixture",
    help="Proof source mode (default: fixture)",
)
@click.option(
    "--assets-dir",
    type=click.Path(),
    default="privacy_circuits/params",
    help="Base directory for fixture assets",
)
@click.option(
    "--strict/--no-strict",
    default=True,
    help="Enable strict request validation",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
def zk_serve(listen_addr, host, port, prove_mode, assets_dir, strict, verbose):
    """
    Serve privacy proof responses over libp2p.
    """
    import trio
    from libp2p import new_host
    from libp2p.tools.async_service import background_trio_service
    from libp2p_privacy_poc.utils import get_peer_listening_address
    from libp2p_privacy_poc.network.privacyzk.protocol import register_privacyzk_protocol
    from libp2p_privacy_poc.network.privacyzk.provider import (
        FixtureProofProvider,
        HybridProofProvider,
        ProviderConfig,
        RealProofProvider,
    )
    from libp2p_privacy_poc.network.privacyzk.prover import make_real_prover_callback

    if not listen_addr:
        listen_addr = f"/ip4/{host}/tcp/{port}"

    async def _wait_for_listen_addr(host_obj, timeout: float = 5.0) -> Multiaddr:
        last_exc = None
        with trio.move_on_after(timeout):
            while True:
                try:
                    return get_peer_listening_address(host_obj)
                except Exception as exc:
                    last_exc = exc
                    await trio.sleep(0.1)
        if last_exc:
            raise last_exc
        raise ValueError("Host has no active listeners")

    config = ProviderConfig(prove_mode=prove_mode, base_dir=assets_dir, strict=strict)
    if prove_mode == "fixture":
        provider = FixtureProofProvider(config)
    elif prove_mode == "real":
        provider = RealProofProvider(
            config,
            prover=make_real_prover_callback(assets_dir),
        )
    else:
        fixture = FixtureProofProvider(ProviderConfig("fixture", base_dir=assets_dir, strict=strict))
        real = RealProofProvider(
            ProviderConfig("real", base_dir=assets_dir, strict=strict),
            prover=make_real_prover_callback(assets_dir),
        )
        provider = HybridProofProvider(config, fixture_provider=fixture, real_provider=real)

    async def _serve():
        host_obj = new_host()
        register_privacyzk_protocol(host_obj, provider)
        network = host_obj.get_network()

        async with background_trio_service(network):
            if verbose:
                click.echo(f"Listening on {listen_addr} ...")
            listen_ok = await network.listen(Multiaddr(listen_addr))
            if not listen_ok:
                click.echo("Error: failed to start listener", err=True)
                return
            peer_id = host_obj.get_id()
            click.echo(f"Peer ID: {peer_id}")
            try:
                actual_addr = await _wait_for_listen_addr(host_obj)
            except Exception as exc:
                if "/tcp/0" in listen_addr:
                    click.echo(f"Error: failed to obtain listening address: {exc}", err=True)
                    return
                actual_addr = Multiaddr(listen_addr).encapsulate(Multiaddr(f"/p2p/{peer_id}"))
                click.echo(f"Warning: using configured listen address; {exc}")
            click.echo(f"Listening: {actual_addr}")
            click.echo("Serving privacyzk protocol. Press Ctrl+C to stop.")
            await trio.sleep_forever()

    try:
        trio.run(_serve)
    except KeyboardInterrupt:
        click.echo("\nStopping privacyzk server...")


@main.command(name="zk-verify")
@click.option(
    "--peer",
    required=True,
    help="Peer ID or full multiaddr (/ip4/.../p2p/<peer-id>)",
)
@click.option(
    "--statement",
    type=click.Choice(["membership", "continuity", "unlinkability"], case_sensitive=False),
    required=True,
    help="Statement type to request",
)
@click.option(
    "--schema",
    type=int,
    default=2,
    show_default=True,
    help="SNARK schema version",
)
@click.option(
    "--depth",
    type=int,
    default=None,
    help="Merkle depth (membership only)",
)
@click.option(
    "--assets-dir",
    type=click.Path(),
    default="privacy_circuits/params",
    help="Base directory for verifier assets",
)
@click.option(
    "--timeout",
    type=int,
    default=10,
    show_default=True,
    help="Request timeout in seconds",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output JSON result",
)
@click.option(
    "--require-real",
    is_flag=True,
    help="Fail if the server did not use real proving",
)
def zk_verify(peer, statement, schema, depth, assets_dir, timeout, as_json, require_real):
    """
    Request a proof from a peer and verify it locally.
    """
    import secrets
    import trio
    from libp2p import new_host
    from libp2p.peer.id import ID
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from libp2p.tools.async_service import background_trio_service
    from libp2p_privacy_poc.network.privacyzk.assets import AssetsResolver
    from libp2p_privacy_poc.network.privacyzk.client import request_proof
    from libp2p_privacy_poc.network.privacyzk.messages import ProofRequest
    from libp2p_privacy_poc.network.privacyzk.constants import (
        DEFAULT_MEMBERSHIP_DEPTH,
        MSG_V,
    )
    from libp2p_privacy_poc.privacy_protocol.snark.backend import SnarkBackend

    statement = statement.lower()
    if depth is None:
        depth = DEFAULT_MEMBERSHIP_DEPTH if statement == "membership" else 0

    if statement != "membership" and depth != 0:
        click.echo("Depth must be 0 for continuity/unlinkability", err=True)
        sys.exit(2)
    if statement == "membership" and depth < 1:
        click.echo("Depth must be >= 1 for membership", err=True)
        sys.exit(2)

    req = ProofRequest(
        msg_v=MSG_V,
        t=statement,
        schema_v=schema,
        d=depth,
        nonce=secrets.token_bytes(16),
    )

    async def _run_request():
        host_obj = new_host()
        network = host_obj.get_network()
        async with background_trio_service(network):
            await network.listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
            if peer.startswith("/"):
                peer_info = info_from_p2p_addr(Multiaddr(peer))
                with trio.fail_after(timeout):
                    await host_obj.connect(peer_info)
                peer_id = peer_info.peer_id
            else:
                peer_id = ID.from_base58(peer)
            with trio.fail_after(timeout):
                return await request_proof(
                    host_obj, peer_id, req, timeout=timeout
                )

    try:
        response = trio.run(_run_request)
    except Exception as exc:
        _emit_result(
            as_json,
            ok=False,
            verified=False,
            statement=statement,
            schema=schema,
            depth=depth,
            error=_format_exception(exc),
        )
        sys.exit(1)

    if response.t != statement or response.schema_v != schema or response.d != depth:
        _emit_result(
            as_json,
            ok=False,
            verified=False,
            statement=statement,
            schema=schema,
            depth=depth,
            error="response metadata mismatch",
        )
        sys.exit(1)

    if not response.ok:
        _emit_result(
            as_json,
            ok=False,
            verified=False,
            statement=statement,
            schema=schema,
            depth=depth,
            error=response.err or "proof request failed",
        )
        sys.exit(1)

    if require_real:
        prove_mode = None
        meta_bytes = getattr(response, "meta", b"") or b""
        if meta_bytes:
            try:
                import cbor2

                meta = cbor2.loads(meta_bytes)
                prove_mode = meta.get("prove_mode")
            except Exception:
                prove_mode = None
        if prove_mode != "real":
            _emit_result(
                as_json,
                ok=False,
                verified=False,
                statement=statement,
                schema=schema,
                depth=depth,
                error=f"expected prove_mode=real, got {prove_mode or 'unknown'}",
            )
            sys.exit(1)

    try:
        resolver = AssetsResolver(assets_dir)
        fixture = resolver.resolve_fixture(statement, schema, depth)
    except Exception as exc:
        _emit_result(
            as_json,
            ok=True,
            verified=False,
            statement=statement,
            schema=schema,
            depth=depth,
            error=f"vk resolution failed: {exc}",
        )
        sys.exit(1)

    verified = SnarkBackend.verify(
        statement_type=statement,
        schema_version=schema,
        vk=str(fixture.vk_path),
        public_inputs=response.public_inputs,
        proof=response.proof,
    )

    _emit_result(
        as_json,
        ok=True,
        verified=verified,
        statement=statement,
        schema=schema,
        depth=depth,
        error=None if verified else "verification failed",
    )
    sys.exit(0 if verified else 2)


@main.command(name="zk-dial")
@click.option(
    "--peer",
    required=True,
    help="Peer multiaddr to connect to (/ip4/.../p2p/<peer-id>)",
)
@click.option(
    "--count",
    type=int,
    default=1,
    show_default=True,
    help="Number of concurrent dialers",
)
@click.option(
    "--duration",
    type=int,
    default=10,
    show_default=True,
    help="Seconds to keep connections open",
)
def zk_dial(peer, count, duration):
    """
    Dial a peer to create inbound connections during analysis.
    """
    import trio
    from libp2p import new_host
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from libp2p.tools.async_service import background_trio_service

    if count < 1:
        click.echo("Count must be >= 1", err=True)
        sys.exit(2)
    if not peer.startswith("/"):
        click.echo("Peer must be a full multiaddr", err=True)
        sys.exit(2)

    peer_info = info_from_p2p_addr(Multiaddr(peer))
    click.echo(f"Dialing {peer} with {count} peer(s) for {duration}s")

    async def _dial_one() -> None:
        host_obj = new_host()
        network = host_obj.get_network()
        async with background_trio_service(network):
            await network.listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
            await host_obj.connect(peer_info)
            await trio.sleep(duration)
        await host_obj.close()

    async def _run() -> None:
        async with trio.open_nursery() as nursery:
            for _ in range(count):
                nursery.start_soon(_dial_one)

    try:
        trio.run(_run)
    except KeyboardInterrupt:
        click.echo("Stopping dialers...")
    except Exception as exc:
        click.echo(f"Dial failed: {_format_exception(exc)}", err=True)
        sys.exit(1)


def _format_exception(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup):
        parts = []
        for sub_exc in exc.exceptions:
            msg = _format_exception(sub_exc)
            if msg:
                parts.append(msg)
        return "; ".join(parts) if parts else str(exc)
    return str(exc)


def _emit_result(as_json, ok, verified, statement, schema, depth, error):
    if as_json:
        payload = {
            "ok": ok,
            "verified": verified,
            "statement": statement,
            "schema": schema,
            "depth": depth,
            "error": error,
        }
        click.echo(json.dumps(payload))
    else:
        if verified:
            click.echo(click.style("PASS", fg="green"))
        else:
            click.echo(click.style("FAIL", fg="red"))
        if error:
            click.echo(f"Error: {error}")


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
