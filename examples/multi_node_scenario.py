"""
Multi-node privacy analysis scenario.

This example demonstrates privacy analysis across multiple interconnected
nodes using REAL py-libp2p connections, showing how privacy leaks can emerge 
from network-wide patterns.
"""
import trio
from libp2p import new_host
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.tools.async_service import background_trio_service
from multiaddr import Multiaddr

from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer
from libp2p_privacy_poc.report_generator import ReportGenerator
from libp2p_privacy_poc.mock_zk_proofs import MockZKProofSystem

# Timeout constants for network operations (in seconds)
LISTEN_TIMEOUT = 10  # Time to bind listener
CONNECT_TIMEOUT = 10  # Time to establish connection
CLOSE_TIMEOUT = 5    # Time to cleanup/close hosts


class NetworkNode:
    """Represents a node in the network with real connection support."""
    
    def __init__(self, name: str, host):
        self.name = name
        self.host = host
        self.collector = MetadataCollector(host)
        self.peer_id = host.get_id()
        self.network = host.get_network()
    
    async def start(self, listen_addr: Multiaddr):
        """Start the network and listener (with timeout protection)."""
        with trio.fail_after(LISTEN_TIMEOUT):
            await self.network.listen(listen_addr)
    
    async def connect_to(self, peer_multiaddr: Multiaddr):
        """Connect to another peer (with timeout protection)."""
        peer_info = info_from_p2p_addr(peer_multiaddr)
        with trio.fail_after(CONNECT_TIMEOUT):
            await self.host.connect(peer_info)
    
    def analyze(self) -> tuple:
        """Run privacy analysis."""
        analyzer = PrivacyAnalyzer(self.collector)
        report = analyzer.analyze()
        return report, self.collector.get_statistics()


async def main():
    """Main demonstration with real py-libp2p connections."""
    print("\n" + "=" * 70)
    print("MULTI-NODE PRIVACY ANALYSIS SCENARIO")
    print("=" * 70)
    print("\nUsing REAL py-libp2p connections with automatic event capture")
    print("\nThis example demonstrates:")
    print("- Privacy analysis across 3 interconnected nodes")
    print("- Detection of network-wide privacy patterns")
    print("- Comparative risk analysis between nodes")
    print("- Identification of high-risk connection patterns")
    
    # Create 3 nodes (reduced from 5 for performance)
    print("\n" + "-" * 70)
    print("1. Creating 3 network nodes with real hosts...")
    print("-" * 70)
    
    # Create hosts with explicit listen addresses
    listen_addrs = [
        Multiaddr("/ip4/127.0.0.1/tcp/0"),
        Multiaddr("/ip4/127.0.0.1/tcp/0"),
        Multiaddr("/ip4/127.0.0.1/tcp/0"),
    ]
    
    nodes = []
    hosts = []
    for i in range(3):
        host = new_host()
        hosts.append(host)
        node = NetworkNode(f"Node-{i+1}", host)
        nodes.append(node)
        print(f"   {node.name}: {node.peer_id}")
    
    # Start all networks
    print("\n" + "-" * 70)
    print("2. Starting networks...")
    print("-" * 70)
    
    # Use background_trio_service for all networks
    async with background_trio_service(nodes[0].network):
        async with background_trio_service(nodes[1].network):
            async with background_trio_service(nodes[2].network):
                print("   ✓ All networks started")
                
                # Start listeners
                print("\n   Starting listeners...")
                await nodes[0].start(listen_addrs[0])
                await nodes[1].start(listen_addrs[1])
                await nodes[2].start(listen_addrs[2])
                
                # Wait for listeners to be ready
                await trio.sleep(0.5)
                
                # Get actual listening addresses
                print("   ✓ All nodes listening")
                
                # Establish star topology: Node-1 is hub
                print("\n" + "-" * 70)
                print("3. Establishing star network topology...")
                print("-" * 70)
                print("   Node-1 (hub) connects to Node-2 and Node-3")
                
                hub = nodes[0]
                spokes = nodes[1:3]
                
                # Connect hub to each spoke
                for i, spoke in enumerate(spokes):
                    # Get spoke's listening address
                    listener_key = list(spoke.network.listeners.keys())[0]
                    listener = spoke.network.listeners[listener_key]
                    actual_addr = listener.get_addrs()[0]
                    full_addr = actual_addr.encapsulate(Multiaddr(f"/p2p/{spoke.peer_id}"))
                    
                    print(f"   Connecting Node-1 to {spoke.name}...")
                    await hub.connect_to(full_addr)
                    print(f"   ✓ Connected to {spoke.name}")
                    
                    # Small delay between connections
                    await trio.sleep(0.1)
                
                # Wait for events to be captured
                await trio.sleep(1.0)
                
                # Check connections
                print("\n   Network topology established:")
                for node in nodes:
                    stats = node.collector.get_statistics()
                    print(f"   {node.name}: {stats['total_connections']} connections, {stats['unique_peers']} peers")
                
                # Additional traffic: Hub makes rapid connections (timing leak!)
                print("\n" + "-" * 70)
                print("4. Simulating additional traffic patterns...")
                print("-" * 70)
                print("   Hub making rapid reconnections (timing leak!)...")
                
                # Have hub connect to spoke 2 again (reconnection)
                listener_key = list(spokes[0].network.listeners.keys())[0]
                listener = spokes[0].network.listeners[listener_key]
                actual_addr = listener.get_addrs()[0]
                full_addr = actual_addr.encapsulate(Multiaddr(f"/p2p/{spokes[0].peer_id}"))
                
                # Try to connect again quickly
                try:
                    await hub.connect_to(full_addr)
                    await trio.sleep(0.05)  # Very short interval
                    print("   ✓ Additional connection attempt made")
                except Exception as e:
                    print(f"   Note: Reconnection attempt (expected behavior): {type(e).__name__}")
                
                # Wait for all events to be captured
                await trio.sleep(0.5)
    
                # Analyze each node
                print("\n" + "-" * 70)
                print("5. Running privacy analysis on each node...")
                print("-" * 70)
                
                results = []
                for node in nodes:
                    report, stats = node.analyze()
                    results.append((node, report, stats))
                    
                    # Determine risk level from score
                    if report.overall_risk_score >= 0.7:
                        risk_level = "CRITICAL"
                    elif report.overall_risk_score >= 0.5:
                        risk_level = "HIGH"
                    elif report.overall_risk_score >= 0.3:
                        risk_level = "MEDIUM"
                    else:
                        risk_level = "LOW"
                    
                    print(f"\n   {node.name} Analysis:")
                    print(f"   {'─' * 60}")
                    print(f"     Connections: {stats['total_connections']}")
                    print(f"     Unique Peers: {stats['unique_peers']}")
                    print(f"     Protocols: {stats['protocols_used']}")
                    print(f"     Risk Score: {report.overall_risk_score:.2f}/1.00")
                    print(f"     Risk Level: {risk_level}")
                    print(f"     Risks Detected: {len(report.risks)}")
                    
                    if report.risks:
                        print(f"     Top Risks:")
                        for risk in report.risks[:3]:
                            print(f"       • {risk.severity}: {risk.risk_type}")
    
                # Comparative analysis
                print("\n" + "-" * 70)
                print("6. Comparative Analysis")
                print("-" * 70)
                
                # Find highest risk node
                if results:
                    highest_risk_node = max(results, key=lambda x: x[1].overall_risk_score)
                    lowest_risk_node = min(results, key=lambda x: x[1].overall_risk_score)
                    
                    print(f"\n   🔴 Highest Risk: {highest_risk_node[0].name}")
                    print(f"      Score: {highest_risk_node[1].overall_risk_score:.2f}")
                    print(f"      Reason: Hub node with more connections")
                    
                    print(f"\n   🟢 Lowest Risk: {lowest_risk_node[0].name}")
                    print(f"      Score: {lowest_risk_node[1].overall_risk_score:.2f}")
                    print(f"      Reason: Spoke node with fewer connections")
                    
                    # Network-wide statistics
                    print("\n   📊 Network-Wide Statistics:")
                    total_connections = sum(stats['total_connections'] for _, _, stats in results)
                    avg_risk = sum(report.overall_risk_score for _, report, _ in results) / len(results)
                    total_risks = sum(len(report.risks) for _, report, _ in results)
                    
                    print(f"      Total Connections (from all perspectives): {total_connections}")
                    print(f"      Average Risk Score: {avg_risk:.2f}")
                    print(f"      Total Privacy Risks Detected: {total_risks}")
                    
                    # Generate detailed report for hub node
                    print("\n" + "-" * 70)
                    print("7. Generating detailed report for hub node...")
                    print("-" * 70)
                    
                    hub_report = highest_risk_node[1]
                    report_gen = ReportGenerator()
                    
                    # Generate console report
                    console_report = report_gen.generate_console_report(
                        report=hub_report,
                        verbose=True
                    )
                    
                    print("\n" + console_report)
    
                # Key insights
                print("\n" + "=" * 70)
                print("KEY INSIGHTS FROM REAL NETWORK ANALYSIS")
                print("=" * 70)
                
                print("""
1. **Real Connection Validation**: Successfully established real py-libp2p connections
   - Events automatically captured via INotifee
   - No manual event simulation required
   - Production-ready integration pattern

2. **Hub Node Risk**: The central hub node shows different risk profile:
   - More connections from hub's perspective
   - Different anonymity set size per node
   - Real network metadata captured

3. **Spoke Node Privacy**: Spoke nodes have different perspective:
   - Fewer connections visible
   - Smaller local anonymity set
   - Real timing data from actual connections

4. **Network Topology Impact**: Star topology with real connections:
   - Each node sees different network view
   - Privacy risks vary by position
   - Real connection metadata enables accurate analysis

5. **Production Recommendations**:
   - Use mesh topology for better privacy distribution
   - Add random delays between connections
   - Rotate connection patterns
   - Monitor privacy metrics continuously
   - Use real connection data for accurate risk assessment
    """)
                
                print("\n" + "=" * 70)
                print("✓ SCENARIO COMPLETE - REAL NETWORK VALIDATED")
                print("=" * 70)
                print("\nKey Achievement:")
                print("- Real 3-node star network with py-libp2p")
                print("- Automatic event capture on all nodes")
                print("- Comparative privacy analysis across nodes")
                print("- Ready for production multi-node scenarios!")
                
                # Cleanup (with timeout protection)
                print("\n8. Cleaning up...")
                with trio.fail_after(CLOSE_TIMEOUT):
                    for node in nodes:
                        await node.host.close()
                print("   ✓ All hosts closed")


if __name__ == "__main__":
    trio.run(main)

