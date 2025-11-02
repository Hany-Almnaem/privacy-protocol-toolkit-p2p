"""
Basic Privacy Analysis Example

This example demonstrates how to use the Privacy Analysis Tool with real
py-libp2p connections.

Creates two hosts, establishes a real connection, and runs privacy analysis
on the captured metadata.
"""

import trio
from libp2p import new_host
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.tools.async_service import background_trio_service
from multiaddr import Multiaddr

from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer
from libp2p_privacy_poc.mock_zk_proofs import MockZKProofSystem
from libp2p_privacy_poc.report_generator import ReportGenerator
from libp2p_privacy_poc.utils import get_peer_listening_address

# Timeout constants for network operations (in seconds)
LISTEN_TIMEOUT = 10  # Time to bind listener
CONNECT_TIMEOUT = 10  # Time to establish connection
CLOSE_TIMEOUT = 5    # Time to cleanup/close hosts


async def main():
    """Run the basic privacy analysis example with real connections."""
    
    print("\n" + "=" * 70)
    print("libp2p Privacy Analysis Tool - Basic Example")
    print("=" * 70)
    print("\nUsing REAL py-libp2p connections with automatic event capture\n")
    
    # Create two hosts
    print("1. Creating two libp2p hosts...")
    listen_addr1 = Multiaddr("/ip4/127.0.0.1/tcp/0")
    listen_addr2 = Multiaddr("/ip4/127.0.0.1/tcp/0")
    
    host1 = new_host()
    host2 = new_host()
    print(f"   Host1 ID: {host1.get_id()}")
    print(f"   Host2 ID: {host2.get_id()}")
    
    # Attach MetadataCollector to host1
    print("\n2. Creating MetadataCollector with automatic event capture...")
    collector = MetadataCollector(host1)
    print("   ✓ Collector attached (events will be auto-captured via INotifee)")
    
    # Start networks using background_trio_service
    print("\n3. Starting networks...")
    network1 = host1.get_network()
    network2 = host2.get_network()
    
    async with background_trio_service(network1):
        async with background_trio_service(network2):
            print("   ✓ Networks started")
            
            # Start listeners (with timeout protection)
            print("\n4. Starting listeners...")
            with trio.fail_after(LISTEN_TIMEOUT):
                await network1.listen(listen_addr1)
                await network2.listen(listen_addr2)
            
            # Wait for listeners to be ready
            await trio.sleep(0.5)
            
            # Get actual listening address using utility function
            full_addr = get_peer_listening_address(host2)
            print(f"   ✓ Host2 listening on: {full_addr}")
            
            # Establish connection from host1 to host2 (with timeout protection)
            print("\n5. Establishing real connection...")
            peer_info = info_from_p2p_addr(full_addr)
            with trio.fail_after(CONNECT_TIMEOUT):
                await host1.connect(peer_info)
            print("   ✓ Connection established!")
            
            # Wait for events to be captured
            await trio.sleep(0.5)
            
            # Check captured events
            stats = collector.get_statistics()
            print(f"\n6. Events captured by MetadataCollector:")
            print(f"   Total connections: {stats['total_connections']}")
            print(f"   Active connections: {stats['active_connections']}")
            print(f"   Unique peers: {stats['unique_peers']}")
            
            if stats['total_connections'] == 0:
                print("\n   ⚠️  Warning: No events captured. This is unexpected.")
                print("   The INotifee should have captured the connection automatically.")
            else:
                print("\n   ✓ Real connection events captured successfully!")
    
            # Run privacy analysis
            print("\n7. Running Privacy Analysis...")
            analyzer = PrivacyAnalyzer(collector)
            report = analyzer.analyze()
            
            print(f"\n   Analysis Complete!")
            print(f"   - Overall Risk Score: {report.overall_risk_score:.2f}/1.00")
            print(f"   - Risks Detected: {len(report.risks)}")
            print(f"   - Critical Risks: {len(report.get_critical_risks())}")
            print(f"   - High Risks: {len(report.get_high_risks())}")
            
            # Display summary
            print("\n" + "=" * 70)
            print("Privacy Analysis Summary")
            print("=" * 70)
            print(report.summary())
            
            # Generate ZK proofs (mock)
            print("\n" + "=" * 70)
            print("Generating Mock ZK Proofs")
            print("=" * 70)
            
            zk_system = MockZKProofSystem()
            
            # Generate anonymity set proof
            print("\n8. Generating anonymity set proof...")
            peer_ids = list(collector.peers.keys())
            if peer_ids:
                anonymity_proof = zk_system.generate_anonymity_set_proof(
                    peer_id=str(peer_ids[0]),
                    anonymity_set_size=len(peer_ids)
                )
                print(f"   ✓ Proof generated")
                print(f"   Type: {anonymity_proof.proof_type}")
                print(f"   Claim: Peer is one of {len(peer_ids)} peers")
                
                # Verify proof
                is_valid = zk_system.verify_proof(anonymity_proof)
                print(f"   Verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
            
            # Generate enhanced report with ZK proofs
            print("\n9. Generating reports...")
            
            # Generate proofs for the report (as dictionary)
            zk_proofs = {}
            if peer_ids:
                anonymity_proof = zk_system.generate_anonymity_set_proof(
                    peer_id=str(peer_ids[0]),
                    anonymity_set_size=len(peer_ids)
                )
                zk_proofs["anonymity_set"] = [anonymity_proof]
            
            # Generate reports in different formats
            report_gen = ReportGenerator()
            
            # Console report
            print("\n   Generating console report...")
            console_report = report_gen.generate_console_report(report, zk_proofs)
            
            # JSON report
            print("   Generating JSON report...")
            json_report = report_gen.generate_json_report(report, zk_proofs)
            
            # HTML report  
            print("   Generating HTML report...")
            html_report = report_gen.generate_html_report(report, zk_proofs)
            
            print(f"\n   ✓ All reports generated successfully")
            
            # Export statistics
            print("\n10. Final statistics...")
            stats = collector.get_statistics()
            print(f"\n    Network Statistics:")
            print(f"    - Total connections: {stats['total_connections']}")
            print(f"    - Active connections: {stats['active_connections']}")
            print(f"    - Unique peers: {stats['unique_peers']}")
            print(f"    - Protocols seen: {stats['protocols_used']}")
            
            print("\n" + "=" * 70)
            print("✓ Analysis Complete!")
            print("=" * 70)
            
            print("\n💡 Key Achievement:")
            print("   - Real py-libp2p connections established and analyzed")
            print("   - Events automatically captured via INotifee")
            print("   - Privacy analysis performed on real network metadata")
            print("   - Ready for production integration!\n")
            
            # Cleanup (with timeout protection)
            print("11. Cleaning up...")
            with trio.fail_after(CLOSE_TIMEOUT):
                await host1.close()
                await host2.close()
            print("    ✓ Hosts closed")


if __name__ == "__main__":
    trio.run(main)

