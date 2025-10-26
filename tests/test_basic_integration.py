"""
Basic integration test for the privacy analysis pipeline.

This test uses simulated data to validate the complete pipeline:
MetadataCollector -> PrivacyAnalyzer -> Report Generation

Fast and reliable for CI/CD without network complexity.
For real network tests, see test_real_connection.py and test_multi_peer_real.py
"""
import trio
import pytest
from libp2p import new_host
from multiaddr import Multiaddr

from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer
from libp2p_privacy_poc.report_generator import ReportGenerator


@pytest.mark.trio
async def test_basic_pipeline_integration():
    """Test complete privacy analysis pipeline with simulated events."""
    
    print("\n" + "=" * 60)
    print("Testing Basic Pipeline Integration (Simulated Data)")
    print("=" * 60)
    
    # Create a host (for API structure, not for actual connections)
    print("\n1. Creating host for API structure...")
    host = new_host()
    print(f"   Host ID: {host.get_id()}")
    
    # Create collector (without real event hooks)
    print("\n2. Creating MetadataCollector...")
    collector = MetadataCollector(libp2p_host=None)  # No real hooks
    
    # Simulate connection events
    print("\n3. Simulating connection events...")
    
    # Simulate 3 peers connecting
    for i in range(3):
        peer_host = new_host()
        peer_id = str(peer_host.get_id())
        multiaddr = Multiaddr(f"/ip4/192.168.1.{10+i}/tcp/{4000+i}")
        
        collector.on_connection_opened(peer_id, multiaddr, "inbound")
        collector.on_stream_opened(peer_id)
        collector.on_protocol_negotiated(peer_id, "/ipfs/id/1.0.0")
        
        await trio.sleep(0.05)  # Small delay for timing variation
    
    print(f"   Simulated 3 connections")
    
    # Check statistics
    print("\n4. Verifying MetadataCollector...")
    stats = collector.get_statistics()
    print(f"   Total connections: {stats['total_connections']}")
    print(f"   Active connections: {stats['active_connections']}")
    print(f"   Unique peers: {stats['unique_peers']}")
    
    assert stats['total_connections'] == 3, "Should have 3 connections"
    assert stats['unique_peers'] == 3, "Should have 3 unique peers"
    print("   ✓ Data collection verified")
    
    # Run privacy analysis
    print("\n5. Running PrivacyAnalyzer...")
    analyzer = PrivacyAnalyzer(collector)
    report = analyzer.analyze()
    
    print(f"   Risk Score: {report.overall_risk_score:.3f}")
    print(f"   Risks Detected: {len(report.risks)}")
    
    assert 0.0 <= report.overall_risk_score <= 1.0, "Risk score should be in valid range"
    print("   ✓ Privacy analysis completed")
    
    # Generate reports
    print("\n6. Generating reports...")
    report_gen = ReportGenerator()
    
    console_report = report_gen.generate_console_report(report)
    assert len(console_report) > 0
    print("   ✓ Console report generated")
    
    json_report = report_gen.generate_json_report(report)
    assert "overall_risk_score" in json_report
    print("   ✓ JSON report generated")
    
    html_report = report_gen.generate_html_report(report)
    assert "<html" in html_report.lower()
    print("   ✓ HTML report generated")
    
    print("\n" + "=" * 60)
    print("✓ Basic integration test PASSED")
    print("=" * 60)
    
    # Cleanup
    await host.close()


@pytest.mark.trio
async def test_collector_statistics_tracking():
    """Test that MetadataCollector correctly tracks all statistics."""
    
    print("\n" + "=" * 60)
    print("Testing Statistics Tracking")
    print("=" * 60)
    
    collector = MetadataCollector(libp2p_host=None)
    
    # Simulate multiple connection events
    print("\n1. Simulating network activity...")
    
    for i in range(5):
        peer_host = new_host()
        peer_id = str(peer_host.get_id())
        multiaddr = Multiaddr(f"/ip4/10.0.0.{100+i}/tcp/{5000+i}")
        
        # Open connection
        collector.on_connection_opened(peer_id, multiaddr, "outbound")
        await trio.sleep(0.02)
        
        # Simulate protocol negotiation
        collector.on_protocol_negotiated(peer_id, "/test/protocol/1.0.0")
        
        # Simulate streams
        for _ in range(i + 1):  # Different number of streams per peer
            collector.on_stream_opened(peer_id)
    
    print(f"   Simulated 5 connections with varying activity")
    
    # Verify statistics
    print("\n2. Checking statistics...")
    stats = collector.get_statistics()
    
    assert stats['total_connections'] == 5
    assert stats['active_connections'] == 5
    assert stats['unique_peers'] == 5
    assert stats['protocols_used'] >= 1
    
    print(f"   Total connections: {stats['total_connections']} ✓")
    print(f"   Active connections: {stats['active_connections']} ✓")
    print(f"   Unique peers: {stats['unique_peers']} ✓")
    print(f"   Protocols used: {stats['protocols_used']} ✓")
    
    # Verify peer metadata
    print("\n3. Checking peer metadata...")
    all_peers = collector.get_all_peers()
    assert len(all_peers) == 5
    
    for peer in all_peers:
        assert peer.connection_count >= 1
        assert len(peer.protocols) >= 1
        print(f"   Peer {peer.peer_id[:16]}... tracked ✓")
    
    print("\n" + "=" * 60)
    print("✓ Statistics tracking test PASSED")
    print("=" * 60)


@pytest.mark.trio
async def test_connection_lifecycle():
    """Test that connection open/close lifecycle is properly tracked."""
    
    print("\n" + "=" * 60)
    print("Testing Connection Lifecycle")
    print("=" * 60)
    
    collector = MetadataCollector(libp2p_host=None)
    
    # Create peer
    peer_host = new_host()
    peer_id = str(peer_host.get_id())
    multiaddr = Multiaddr("/ip4/172.16.0.10/tcp/6000")
    
    print("\n1. Opening connection...")
    collector.on_connection_opened(peer_id, multiaddr, "inbound")
    
    stats_after_open = collector.get_statistics()
    assert stats_after_open['active_connections'] == 1
    assert stats_after_open['total_connections'] == 1
    print("   ✓ Connection opened and tracked")
    
    # Hold connection for a moment
    await trio.sleep(0.5)
    
    print("\n2. Closing connection...")
    collector.on_connection_closed(peer_id, multiaddr)
    
    stats_after_close = collector.get_statistics()
    assert stats_after_close['active_connections'] == 0
    assert stats_after_close['total_disconnections'] == 1
    assert len(collector.connection_history) == 1
    print("   ✓ Connection closed and moved to history")
    
    # Verify connection duration was calculated
    closed_conn = collector.connection_history[0]
    assert closed_conn.timestamp_end is not None
    assert closed_conn.connection_duration is not None
    assert closed_conn.connection_duration > 0
    print(f"   ✓ Connection duration: {closed_conn.connection_duration:.2f}s")
    
    print("\n" + "=" * 60)
    print("✓ Connection lifecycle test PASSED")
    print("=" * 60)
    
    await peer_host.close()


if __name__ == "__main__":
    # Run tests directly
    async def run_tests():
        await test_basic_pipeline_integration()
        await trio.sleep(0.5)
        await test_collector_statistics_tracking()
        await trio.sleep(0.5)
        await test_connection_lifecycle()
    
    trio.run(run_tests)
