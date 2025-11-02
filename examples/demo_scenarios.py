"""
Privacy Analysis Demo Scenarios.

This script demonstrates different privacy leak scenarios using REAL py-libp2p 
connections and shows how the analysis tool detects them, along with ZK proof demonstrations.

Each scenario is self-contained and includes:
1. Real network setup with py-libp2p
2. Privacy analysis on real connections
3. ZK proof generation
4. Results and interpretation
"""
import trio
from libp2p import new_host
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.tools.async_service import background_trio_service
from multiaddr import Multiaddr

from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer
from libp2p_privacy_poc.report_generator import ReportGenerator
from libp2p_privacy_poc.mock_zk_proofs import MockZKProofSystem, ZKProofType

# Timeout constants for network operations (in seconds)
LISTEN_TIMEOUT = 10  # Time to bind listener
CONNECT_TIMEOUT = 10  # Time to establish connection
CLOSE_TIMEOUT = 5    # Time to cleanup/close hosts


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_subheader(title: str):
    """Print a formatted subheader."""
    print("\n" + "-" * 70)
    print(f"  {title}")
    print("-" * 70)


async def scenario_1_timing_correlation():
    """
    Scenario 1: Timing Correlation Attack
    
    This scenario demonstrates how rapid, sequential connections can
    create timing correlations that leak privacy information using REAL connections.
    """
    print_header("SCENARIO 1: Timing Correlation Attack (REAL CONNECTIONS)")
    
    print("\n📖 Description:")
    print("   A node makes multiple connections in rapid succession, creating")
    print("   a distinctive timing pattern that can be used to identify the node.")
    
    print_subheader("Real Network Setup")
    
    # Create hub host and multiple target hosts
    hub_host = new_host()
    collector = MetadataCollector(hub_host)
    
    # Create 3 peer hosts (reduced from 5 for speed)
    peer_hosts = [new_host() for _ in range(3)]
    
    print(f"   Hub: {hub_host.get_id()}")
    for i, peer in enumerate(peer_hosts):
        print(f"   Peer {i+1}: {peer.get_id()}")
    
    # Start networks
    print("\n   Starting networks...")
    async with background_trio_service(hub_host.get_network()):
        peer_services = [background_trio_service(peer.get_network()) for peer in peer_hosts]
        
        async with peer_services[0]:
            async with peer_services[1]:
                async with peer_services[2]:
                    # Start listeners (with timeout protection)
                    with trio.fail_after(LISTEN_TIMEOUT):
                        await hub_host.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                        for peer in peer_hosts:
                            await peer.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                    
                    await trio.sleep(0.5)
                    print("   ✓ Networks ready")
                    
                    # Make rapid connections (BAD - creates timing correlation)
                    print("\n   Making 3 connections in rapid succession...")
                    for i, peer in enumerate(peer_hosts):
                        # Get peer's listening address
                        listener_key = list(peer.get_network().listeners.keys())[0]
                        listener = peer.get_network().listeners[listener_key]
                        actual_addr = listener.get_addrs()[0]
                        full_addr = actual_addr.encapsulate(Multiaddr(f"/p2p/{peer.get_id()}"))
                        
                        # Connect with very short delay - THIS IS THE LEAK! (with timeout protection)
                        with trio.fail_after(CONNECT_TIMEOUT):
                            await hub_host.connect(info_from_p2p_addr(full_addr))
                        await trio.sleep(0.05)  # 50ms interval = timing correlation!
                    
                    # Wait for events to be captured
                    await trio.sleep(0.5)
                    print("   ✓ Connections made with 50ms intervals (timing leak!)")
    
                    # Analyze
                    print_subheader("Analysis")
                    stats = collector.get_statistics()
                    print(f"   Total connections: {stats['total_connections']}")
                    
                    analyzer = PrivacyAnalyzer(collector)
                    report = analyzer.analyze()
                    
                    print(f"   Risk Score: {report.overall_risk_score:.2f}/1.00")
                    print(f"   Total Risks: {len(report.risks)}")
                    timing_risks = [r for r in report.risks if 'Timing' in r.risk_type or 'timing' in r.risk_type.lower()]
                    print(f"   Timing-Related Risks: {len(timing_risks)}")
                    
                    for risk in report.risks[:3]:  # Show top 3 risks
                        print(f"   🔴 {risk.severity.upper()}: {risk.risk_type}")
                        print(f"      {risk.description[:70]}...")
                        if risk.recommendations:
                            print(f"      → {risk.recommendations[0]}")
                    
                    # ZK Proof Demonstration
                    print_subheader("ZK Proof: Timing Independence")
                    zk_system = MockZKProofSystem()
                    
                    proof = zk_system.generate_timing_independence_proof(
                        event_1="connection_1",
                        event_2="connection_2",
                        time_delta=0.05
                    )
                    
                    print(f"   Proof Type: {proof.proof_type.value}")
                    print(f"   Proof Valid: {proof.is_valid}")
                    print(f"\n   With ZK proofs, you could prove that events are timing-independent")
                    print(f"   without revealing the actual timing values!")
                    
                    # Cleanup (with timeout protection)
                    print("\n   Cleaning up...")
                    with trio.fail_after(CLOSE_TIMEOUT):
                        await hub_host.close()
                        for peer in peer_hosts:
                            await peer.close()
    
    print("\n✅ Scenario 1 Complete (Real Network)")


async def scenario_2_anonymity_set():
    """
    Scenario 2: Small Anonymity Set
    
    This scenario demonstrates how connecting to too few peers reduces
    anonymity and makes the node easier to identify using REAL connections.
    """
    print_header("SCENARIO 2: Small Anonymity Set (REAL CONNECTIONS)")
    
    print("\n📖 Description:")
    print("   A node connects to only 2 peers, creating a very small anonymity set.")
    print("   This makes it easier to identify and correlate the node's activity.")
    
    print_subheader("Real Network Setup")
    
    # Create host and 2 peers only - VERY BAD for privacy!
    main_host = new_host()
    collector = MetadataCollector(main_host)
    
    peer_hosts = [new_host() for _ in range(2)]
    
    print(f"   Main: {main_host.get_id()}")
    print(f"   Peer 1: {peer_hosts[0].get_id()}")
    print(f"   Peer 2: {peer_hosts[1].get_id()}")
    print("   ⚠️  Only 2 peers - small anonymity set!")
    
    # Start networks
    print("\n   Starting networks...")
    async with background_trio_service(main_host.get_network()):
        async with background_trio_service(peer_hosts[0].get_network()):
            async with background_trio_service(peer_hosts[1].get_network()):
                # Start listeners (with timeout protection)
                with trio.fail_after(LISTEN_TIMEOUT):
                    await main_host.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                    await peer_hosts[0].get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                    await peer_hosts[1].get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                
                await trio.sleep(0.5)
                print("   ✓ Networks ready")
                
                # Connect to both peers
                print("\n   Connecting to only 2 peers...")
                for peer in peer_hosts:
                    listener_key = list(peer.get_network().listeners.keys())[0]
                    listener = peer.get_network().listeners[listener_key]
                    actual_addr = listener.get_addrs()[0]
                    full_addr = actual_addr.encapsulate(Multiaddr(f"/p2p/{peer.get_id()}"))
                    
                    with trio.fail_after(CONNECT_TIMEOUT):
                        await main_host.connect(info_from_p2p_addr(full_addr))
                    await trio.sleep(0.1)
                
                # Wait for events
                await trio.sleep(0.5)
                print(f"   ✓ Connected to 2 peers only (privacy risk!)")
    
                # Analyze
                print_subheader("Analysis")
                stats = collector.get_statistics()
                print(f"   Total connections: {stats['total_connections']}")
                print(f"   Anonymity Set Size: {stats['unique_peers']}")
                
                analyzer = PrivacyAnalyzer(collector)
                report = analyzer.analyze()
                
                print(f"   Risk Score: {report.overall_risk_score:.2f}/1.00")
                anonymity_risks = [r for r in report.risks if 'Anonymity' in r.risk_type or 'anonymity' in r.risk_type.lower()]
                print(f"   Anonymity Risks Detected: {len(anonymity_risks)}")
                
                for risk in report.risks[:3]:
                    print(f"   🔴 {risk.severity.upper()}: {risk.risk_type}")
                    print(f"      {risk.description[:70]}...")
                    if risk.recommendations:
                        print(f"      → {risk.recommendations[0]}")
                
                # ZK Proof Demonstration
                print_subheader("ZK Proof: Anonymity Set Membership")
                zk_system = MockZKProofSystem()
                
                proof = zk_system.generate_anonymity_set_proof(
                    peer_id=str(main_host.get_id()),
                    anonymity_set_size=stats['unique_peers']  # Small set!
                )
                
                print(f"   Proof Type: {proof.proof_type.value}")
                print(f"   Anonymity Set Size: {proof.public_inputs['anonymity_set_size']}")
                print(f"   Proof Valid: {proof.is_valid}")
                print(f"\n   With ZK proofs, you could prove you're one of N peers")
                print(f"   without revealing which one!")
                print(f"   (But N={stats['unique_peers']} is still too small for good privacy!)")
                
                # Cleanup (with timeout protection)
                print("\n   Cleaning up...")
                with trio.fail_after(CLOSE_TIMEOUT):
                    await main_host.close()
                    for peer in peer_hosts:
                        await peer.close()
    
    print("\n✅ Scenario 2 Complete (Real Network)")


async def scenario_3_protocol_fingerprinting():
    """
    Scenario 3: Protocol Fingerprinting
    
    This scenario demonstrates protocol fingerprinting concept with REAL connections.
    Note: In real py-libp2p, protocols are negotiated automatically during connections.
    """
    print_header("SCENARIO 3: Protocol Fingerprinting (REAL CONNECTIONS)")
    
    print("\n📖 Description:")
    print("   Demonstrates how protocol usage patterns can create fingerprints.")
    print("   With real py-libp2p, protocols are negotiated automatically.")
    
    print_subheader("Real Network Setup")
    
    main_host = new_host()
    collector = MetadataCollector(main_host)
    
    # Create 2 peer hosts
    peer_hosts = [new_host() for _ in range(2)]
    
    print(f"   Main: {main_host.get_id()}")
    for i, peer in enumerate(peer_hosts):
        print(f"   Peer {i+1}: {peer.get_id()}")
    
    print("\n   Starting networks...")
    async with background_trio_service(main_host.get_network()):
        async with background_trio_service(peer_hosts[0].get_network()):
            async with background_trio_service(peer_hosts[1].get_network()):
                # Start listeners (with timeout protection)
                with trio.fail_after(LISTEN_TIMEOUT):
                    await main_host.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                    for peer in peer_hosts:
                        await peer.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                
                await trio.sleep(0.5)
                print("   ✓ Networks ready")
                
                # Connect to peers (protocols negotiated automatically)
                print("\n   Making connections (protocols auto-negotiated)...")
                for peer in peer_hosts:
                    listener_key = list(peer.get_network().listeners.keys())[0]
                    listener = peer.get_network().listeners[listener_key]
                    actual_addr = listener.get_addrs()[0]
                    full_addr = actual_addr.encapsulate(Multiaddr(f"/p2p/{peer.get_id()}"))
                    
                    with trio.fail_after(CONNECT_TIMEOUT):
                        await main_host.connect(info_from_p2p_addr(full_addr))
                    await trio.sleep(0.1)
                
                # Wait for events
                await trio.sleep(0.5)
                
                stats = collector.get_statistics()
                print(f"   ✓ Connected to {stats['unique_peers']} peers")
                print(f"   ✓ Protocols observed: {stats['protocols_used']}")
    
                # Analyze
                print_subheader("Analysis")
                analyzer = PrivacyAnalyzer(collector)
                report = analyzer.analyze()
                
                print(f"   Risk Score: {report.overall_risk_score:.2f}/1.00")
                print(f"   Total Risks: {len(report.risks)}")
                protocol_risks = [r for r in report.risks if 'Protocol' in r.risk_type or 'Fingerprint' in r.risk_type]
                print(f"   Protocol/Fingerprint Risks: {len(protocol_risks)}")
                
                for risk in report.risks[:3]:
                    print(f"   🔴 {risk.severity.upper()}: {risk.risk_type}")
                    print(f"      {risk.description[:70]}...")
                    if risk.recommendations:
                        print(f"      → {risk.recommendations[0]}")
                
                print("\n   💡 Insight: Protocol patterns can fingerprint nodes!")
                print("   In production, unusual protocol combinations can make nodes identifiable.")
                
                # Cleanup (with timeout protection)
                print("\n   Cleaning up...")
                with trio.fail_after(CLOSE_TIMEOUT):
                    await main_host.close()
                    for peer in peer_hosts:
                        await peer.close()
    
    print("\n✅ Scenario 3 Complete (Real Network)")


async def scenario_4_zk_proof_showcase():
    """
    Scenario 4: Zero-Knowledge Proof Showcase
    
    This scenario demonstrates all types of ZK proofs available in the
    mock system and explains their privacy benefits.
    (Conceptual demo - focuses on ZK proof concepts, not network connections)
    """
    print_header("SCENARIO 4: Zero-Knowledge Proof Showcase")
    
    print("\n📖 Description:")
    print("   Demonstrating all types of mock ZK proofs and their privacy benefits.")
    
    zk_system = MockZKProofSystem()
    host = new_host()
    
    # 1. Anonymity Set Membership Proof
    print_subheader("1. Anonymity Set Membership Proof")
    print("   Claim: 'I am one of N peers, but I won't tell you which one'")
    
    proof1 = zk_system.generate_anonymity_set_proof(
        peer_id=str(host.get_id()),
        anonymity_set_size=100
    )
    
    print(f"   ✓ Proof Type: {proof1.proof_type.value}")
    print(f"   ✓ Set Size: {proof1.public_inputs['anonymity_set_size']}")
    print(f"   ✓ Valid: {proof1.is_valid}")
    print(f"   ✓ Mock Proof Size: ~128 bytes")
    print(f"\n   Privacy Benefit: Hides your exact identity within a group")
    
    # 2. Session Unlinkability Proof
    print_subheader("2. Session Unlinkability Proof")
    print("   Claim: 'These two sessions cannot be linked to the same peer'")
    
    proof2 = zk_system.generate_unlinkability_proof(
        session_1_id="session_abc123",
        session_2_id="session_def456"
    )
    
    print(f"   ✓ Proof Type: {proof2.proof_type.value}")
    print(f"   ✓ Valid: {proof2.is_valid}")
    print(f"   ✓ Mock Proof Size: ~128 bytes")
    print(f"\n   Privacy Benefit: Prevents tracking across sessions")
    
    # 3. Range Proof
    print_subheader("3. Range Proof (Data Volume)")
    print("   Claim: 'I transferred between X and Y bytes, but not the exact amount'")
    
    proof3 = zk_system.generate_range_proof(
        value_name="data_transfer_bytes",
        min_value=1000,
        max_value=2000,
        actual_value=1500
    )
    
    print(f"   ✓ Proof Type: {proof3.proof_type.value}")
    print(f"   ✓ Range: [{proof3.public_inputs['min_value']}, {proof3.public_inputs['max_value']}]")
    print(f"   ✓ Valid: {proof3.is_valid}")
    print(f"   ✓ Mock Proof Size: ~128 bytes")
    print(f"\n   Privacy Benefit: Hides exact transfer amounts")
    
    # 4. Timing Independence Proof
    print_subheader("4. Timing Independence Proof")
    print("   Claim: 'These events are not timing-correlated'")
    
    proof4 = zk_system.generate_timing_independence_proof(
        event_1="connect",
        event_2="transfer",
        time_delta=5.0
    )
    
    print(f"   ✓ Proof Type: {proof4.proof_type.value}")
    print(f"   ✓ Valid: {proof4.is_valid}")
    print(f"   ✓ Mock Proof Size: ~128 bytes")
    print(f"\n   Privacy Benefit: Prevents timing analysis attacks")
    
    # Batch verification
    print_subheader("Batch Proof Verification")
    print("   Verifying all 4 proofs at once...")
    
    all_proofs = [proof1, proof2, proof3, proof4]
    valid_count = sum(1 for p in all_proofs if zk_system.verify_proof(p))
    
    print(f"   ✓ Valid Proofs: {valid_count}/{len(all_proofs)}")
    print(f"   ✓ Batch verification successful!")
    
    # Proof statistics
    print_subheader("Proof Statistics")
    mock_size_per_proof = 128  # Mock size for demonstration
    total_size = mock_size_per_proof * len(all_proofs)
    print(f"   Total Mock Proof Size: ~{total_size} bytes")
    print(f"   Average Mock Proof Size: ~{mock_size_per_proof} bytes")
    print(f"   Verification Time: < 1ms (mock)")
    
    print("\n   💡 Note: These are MOCK proofs for demonstration.")
    print("      Real ZK proofs would use Groth16, PLONK, or similar schemes.")
    
    # Cleanup (with timeout protection)
    with trio.fail_after(CLOSE_TIMEOUT):
        await host.close()
    
    print("\n✅ Scenario 4 Complete")


async def scenario_5_comprehensive_report():
    """
    Scenario 5: Comprehensive Report Generation
    
    This scenario creates a complex network situation with REAL connections 
    and generates a full privacy report with recommendations.
    """
    print_header("SCENARIO 5: Comprehensive Privacy Report (REAL CONNECTIONS)")
    
    print("\n📖 Description:")
    print("   Creating a scenario with multiple privacy issues using real connections")
    print("   and generating a comprehensive report with ZK proofs.")
    
    print_subheader("Real Network Setup")
    
    main_host = new_host()
    collector = MetadataCollector(main_host)
    
    # Create 3 peers (small anonymity set - privacy issue!)
    peer_hosts = [new_host() for _ in range(3)]
    
    print(f"   Main: {main_host.get_id()}")
    for i, peer in enumerate(peer_hosts):
        print(f"   Peer {i+1}: {peer.get_id()}")
    print("   ⚠️  Small anonymity set + rapid connections = multiple privacy issues!")
    
    print("\n   Starting networks...")
    async with background_trio_service(main_host.get_network()):
        peer_services = [background_trio_service(peer.get_network()) for peer in peer_hosts]
        
        async with peer_services[0]:
            async with peer_services[1]:
                async with peer_services[2]:
                    # Start listeners (with timeout protection)
                    with trio.fail_after(LISTEN_TIMEOUT):
                        await main_host.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                        for peer in peer_hosts:
                            await peer.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
                    
                    await trio.sleep(0.5)
                    print("   ✓ Networks ready")
                    
                    # Make rapid connections (timing issue + small anonymity set)
                    print("\n   Making rapid connections (multiple privacy issues)...")
                    for i, peer in enumerate(peer_hosts):
                        listener_key = list(peer.get_network().listeners.keys())[0]
                        listener = peer.get_network().listeners[listener_key]
                        actual_addr = listener.get_addrs()[0]
                        full_addr = actual_addr.encapsulate(Multiaddr(f"/p2p/{peer.get_id()}"))
                        
                        with trio.fail_after(CONNECT_TIMEOUT):
                            await main_host.connect(info_from_p2p_addr(full_addr))
                        await trio.sleep(0.03)  # Rapid timing - privacy leak!
                    
                    # Wait for events
                    await trio.sleep(0.5)
                    print("   ✓ Complex scenario created")
    
                    # Analyze
                    print_subheader("Analysis")
                    stats = collector.get_statistics()
                    print(f"   Connections: {stats['total_connections']}")
                    print(f"   Unique peers: {stats['unique_peers']}")
                    
                    analyzer = PrivacyAnalyzer(collector)
                    report = analyzer.analyze()
                    
                    print(f"   Risk Score: {report.overall_risk_score:.2f}/1.00")
                    print(f"   Total Risks: {len(report.risks)}")
                    print(f"   Critical: {len(report.get_critical_risks())}")
                    print(f"   High: {len(report.get_high_risks())}")
                    
                    # Generate ZK proofs
                    print_subheader("Generating ZK Proofs")
                    zk_system = MockZKProofSystem()
                    
                    zk_proofs = {
                        "anonymity": [zk_system.generate_anonymity_set_proof(
                            peer_id=str(main_host.get_id()),
                            anonymity_set_size=stats['unique_peers']
                        )],
                        "timing": [zk_system.generate_timing_independence_proof(
                            event_1="conn1",
                            event_2="conn2",
                            time_delta=0.03
                        )]
                    }
                    
                    print(f"   ✓ Generated {sum(len(v) for v in zk_proofs.values())} ZK proofs")
                    
                    # Generate comprehensive report
                    print_subheader("Comprehensive Report")
                    report_gen = ReportGenerator()
                    
                    console_report = report_gen.generate_console_report(
                        report=report,
                        zk_proofs=zk_proofs,
                        verbose=True
                    )
                    
                    print(console_report)
                    
                    # Cleanup (with timeout protection)
                    print("\n   Cleaning up...")
                    with trio.fail_after(CLOSE_TIMEOUT):
                        await main_host.close()
                        for peer in peer_hosts:
                            await peer.close()
    
    print("\n✅ Scenario 5 Complete (Real Network)")


async def main():
    """Run all demo scenarios."""
    print("\n" + "=" * 70)
    print("  PRIVACY ANALYSIS DEMO SCENARIOS")
    print("=" * 70)
    print("\n  This demonstration showcases:")
    print("  • Various privacy leak scenarios")
    print("  • Privacy analysis and risk detection")
    print("  • Zero-knowledge proof concepts")
    print("  • Comprehensive reporting")
    
    scenarios = [
        ("Timing Correlation Attack", scenario_1_timing_correlation),
        ("Small Anonymity Set", scenario_2_anonymity_set),
        ("Protocol Fingerprinting", scenario_3_protocol_fingerprinting),
        ("Zero-Knowledge Proof Showcase", scenario_4_zk_proof_showcase),
        ("Comprehensive Privacy Report", scenario_5_comprehensive_report),
    ]
    
    for i, (name, scenario_func) in enumerate(scenarios, 1):
        print(f"\n\n{'=' * 70}")
        print(f"  Running Scenario {i}/{len(scenarios)}")
        print(f"{'=' * 70}")
        
        await scenario_func()
        
        if i < len(scenarios):
            print("\n  Press Ctrl+C to stop, or wait 2s for next scenario...")
            await trio.sleep(2)
    
    print("\n\n" + "=" * 70)
    print("  ALL SCENARIOS COMPLETE!")
    print("=" * 70)
    print("\n  Key Takeaways:")
    print("  1. Timing correlations leak identity information")
    print("  2. Small anonymity sets reduce privacy significantly")
    print("  3. Unusual protocol usage creates fingerprints")
    print("  4. ZK proofs can prove properties without revealing data")
    print("  5. Multiple small leaks can combine into major privacy risks")
    print("\n  Use these insights to build more private libp2p applications!")
    print("\n")


if __name__ == "__main__":
    trio.run(main)

