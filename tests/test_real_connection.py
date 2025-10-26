"""
Test real py-libp2p connections with latest version.
Run after upgrading to latest py-libp2p from main branch.

UPDATED: Now uses background_trio_service() for proper lifecycle management.
"""
import trio
from libp2p import new_host
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.tools.async_service import background_trio_service
from multiaddr import Multiaddr

from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer
from libp2p_privacy_poc.report_generator import ReportGenerator


async def test_real_connections():
    """Test with latest py-libp2p using background_trio_service."""
    print("\n" + "=" * 70)
    print("TESTING REAL CONNECTIONS WITH LATEST PY-LIBP2P")
    print("Using background_trio_service() pattern from py-libp2p tests")
    print("=" * 70)
    
    # Create two hosts with explicit listen addresses
    print("\n1. Creating hosts...")
    listen_addr1 = Multiaddr("/ip4/127.0.0.1/tcp/10000")
    listen_addr2 = Multiaddr("/ip4/127.0.0.1/tcp/10001")
    
    host1 = new_host(listen_addrs=[listen_addr1])
    host2 = new_host(listen_addrs=[listen_addr2])
    print(f"   Host1: {host1.get_id()}")
    print(f"   Host2: {host2.get_id()}")
    
    # Attach collector
    print("\n2. Attaching MetadataCollector...")
    collector = MetadataCollector(host1)
    
    # Start networks using background_trio_service (the correct way!)
    print("\n3. Starting networks with background_trio_service...")
    network1 = host1.get_network()
    network2 = host2.get_network()
    
    async with background_trio_service(network1) as manager1:
        async with background_trio_service(network2) as manager2:
            print("   ✓ Networks started successfully")
            
            # Start listeners
            print("\n4. Starting listeners...")
            await network1.listen(listen_addr1)
            await network2.listen(listen_addr2)
            
            # Wait for listeners to be ready
            await trio.sleep(1.0)
            
            # Check listeners
            print(f"   Host1 listeners: {len(network1.listeners)}")
            print(f"   Host2 listeners: {len(network2.listeners)}")
            
            if len(network1.listeners) > 0:
                print("   ✅ SUCCESS! Listeners started!")
                
                # Get actual address (listeners is a dict, not a list)
                listener_key = list(network1.listeners.keys())[0]
                listener = network1.listeners[listener_key]
                actual_addr = listener.get_addrs()[0]
                full_addr = actual_addr.encapsulate(Multiaddr(f"/p2p/{host1.get_id()}"))
                print(f"   Host1 listening on: {actual_addr}")
                
                # Try to connect
                print("\n5. Attempting connection...")
                try:
                    peer_info = info_from_p2p_addr(full_addr)
                    await host2.connect(peer_info)
                    print("   ✅ CONNECTION SUCCESSFUL!")
                    
                    # Check collector
                    await trio.sleep(0.5)
                    stats = collector.get_statistics()
                    print(f"\n6. MetadataCollector Statistics:")
                    print(f"   Total connections: {stats['total_connections']}")
                    print(f"   Active connections: {stats['active_connections']}")
                    print(f"   Unique peers: {stats['unique_peers']}")
                    
                    if stats['total_connections'] > 0:
                        print("\n   ✅ REAL EVENT CAPTURE WORKING!")
                        
                        # Run analysis
                        analyzer = PrivacyAnalyzer(collector)
                        report = analyzer.analyze()
                        
                        print(f"\n7. Privacy Analysis:")
                        print(f"   Risk Score: {report.overall_risk_score:.2f}")
                        print(f"   Risks Detected: {len(report.risks)}")
                        
                        # Generate report
                        report_gen = ReportGenerator()
                        console = report_gen.generate_console_report(report, verbose=False)
                        print("\n" + console)
                        
                        print("\n" + "=" * 70)
                        print("🎉 COMPLETE SUCCESS - READY FOR PRODUCTION!")
                        print("=" * 70)
                        print("\nNext steps:")
                        print("1. Update docs to remove 'simulated data' notes")
                        print("2. Update KNOWN_ISSUES.md to mark as RESOLVED")
                        print("3. Post update to GitHub discussion #961")
                        print("4. Consider production hardening phase")
                    else:
                        print("\n   ⚠️ Connection made but events not captured")
                        print("   Check INotifee implementation")
                        
                except Exception as e:
                    print(f"   ✗ Connection failed: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print("   ✗ Listeners still not starting")
                print("   This is unexpected with background_trio_service")
                print("\nDebugging info:")
                print(f"   Manager1 running: {manager1 is not None}")
                print(f"   Manager2 running: {manager2 is not None}")
            
            # Cleanup
            print("\n8. Cleaning up...")
            await host1.close()
            await host2.close()
            print("   ✓ Hosts closed")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("Testing Real Connections with Latest py-libp2p")
    print("=" * 70)
    print("\nMake sure you've run:")
    print("  pip install git+https://github.com/libp2p/py-libp2p.git@main")
    print("=" * 70)
    
    trio.run(test_real_connections)

