# Real Network Integration Guide

> **Status**: Production-Ready Pattern ✅
>
> This guide covers best practices for integrating the libp2p Privacy Analysis Tool with real py-libp2p networks in production environments.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Integration Patterns](#integration-patterns)
3. [Best Practices](#best-practices)
4. [Performance Considerations](#performance-considerations)
5. [Security Guidelines](#security-guidelines)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)
8. [Production Checklist](#production-checklist)

---

## Quick Start

### Minimal Real Network Example

```python
import trio
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from multiaddr import Multiaddr
from libp2p_privacy_poc import MetadataCollector, PrivacyAnalyzer

async def main():
    """Minimal example with real network."""
    # Create host
    host = new_host()
    
    # Attach privacy collector (automatically captures events)
    collector = MetadataCollector(host)
    
    # Start network
    network = host.get_network()
    async with background_trio_service(network):
        # Start listening
        await network.listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
        
        # Your application runs here...
        await trio.sleep(10)  # Monitor for 10 seconds
        
        # Analyze privacy
        report = PrivacyAnalyzer(collector).analyze()
        print(f"Risk Score: {report.overall_risk_score:.2f}")

trio.run(main)
```

### Key Concepts

1. **`background_trio_service()`** - Manages py-libp2p network lifecycle
2. **`MetadataCollector`** - Implements `INotifee` for automatic event capture
3. **Events are automatic** - No manual calls to `on_connection_opened()` needed
4. **Real connections only** - All metadata comes from live network activity

---

## Integration Patterns

### Pattern 1: Attach to Existing Application

If you already have a py-libp2p application, add privacy monitoring with minimal changes:

```python
import trio
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from libp2p_privacy_poc import MetadataCollector, PrivacyAnalyzer

async def my_libp2p_app():
    """Your existing py-libp2p application."""
    host = new_host()
    
    # ADD THIS: Attach privacy monitoring
    privacy_collector = MetadataCollector(host)
    
    # Your existing network setup
    network = host.get_network()
    async with background_trio_service(network):
        await network.listen(Multiaddr("/ip4/0.0.0.0/tcp/4001"))
        
        # Your existing application logic
        await my_business_logic(host)
        
        # ADD THIS: Periodic privacy analysis
        async with trio.open_nursery() as nursery:
            nursery.start_soon(run_application, host)
            nursery.start_soon(periodic_privacy_check, privacy_collector)

async def periodic_privacy_check(collector, interval=300):
    """Check privacy every 5 minutes."""
    while True:
        await trio.sleep(interval)
        report = PrivacyAnalyzer(collector).analyze()
        if report.overall_risk_score > 0.7:
            print(f"⚠️  HIGH PRIVACY RISK: {report.overall_risk_score:.2f}")
            # Take action: log, alert, adjust behavior, etc.
```

### Pattern 2: Multi-Node Network Analysis

For networks with multiple nodes:

```python
import trio
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from libp2p.peer.peerinfo import info_from_p2p_addr
from multiaddr import Multiaddr
from libp2p_privacy_poc import MetadataCollector, PrivacyAnalyzer
from libp2p_privacy_poc.utils import get_peer_listening_address

async def multi_node_network():
    """Create and analyze a multi-node network."""
    # Create nodes
    nodes = [new_host() for _ in range(3)]
    collectors = [MetadataCollector(node) for node in nodes]
    
    # Start all networks concurrently
    async with trio.open_nursery() as nursery:
        # Start services
        for node in nodes:
            nursery.start_soon(
                lambda n: background_trio_service(n.get_network()).__aenter__(),
                node
            )
        
        # Wait for services to start
        await trio.sleep(0.5)
        
        # Start listeners
        for node in nodes:
            await node.get_network().listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
        
        # Connect nodes in star topology (node0 is hub)
        for i in range(1, len(nodes)):
            peer_addr = get_peer_listening_address(nodes[i])
            peer_info = info_from_p2p_addr(peer_addr)
            await nodes[0].connect(peer_info)
        
        # Monitor network activity
        await trio.sleep(10)
        
        # Analyze from each node's perspective
        for i, collector in enumerate(collectors):
            report = PrivacyAnalyzer(collector).analyze()
            print(f"Node {i} Risk Score: {report.overall_risk_score:.2f}")

trio.run(multi_node_network)
```

### Pattern 3: Connection-Specific Analysis

Analyze privacy for specific peer connections:

```python
async def analyze_peer_connection(host, peer_multiaddr):
    """Analyze privacy of connecting to a specific peer."""
    collector = MetadataCollector(host)
    
    network = host.get_network()
    async with background_trio_service(network):
        await network.listen(Multiaddr("/ip4/127.0.0.1/tcp/0"))
        
        # Connect to target peer with timeout
        peer_info = info_from_p2p_addr(peer_multiaddr)
        with trio.fail_after(10):  # 10 second timeout
            await host.connect(peer_info)
        
        # Monitor connection for a period
        await trio.sleep(30)
        
        # Analyze privacy of this specific connection
        report = PrivacyAnalyzer(collector).analyze()
        
        # Check peer-specific risks
        peer_id = str(peer_info.peer_id)
        if peer_id in collector.peers:
            peer_data = collector.peers[peer_id]
            print(f"Connection count: {peer_data['connection_count']}")
            print(f"Protocols: {peer_data.get('protocols', [])}")
        
        return report
```

### Pattern 4: Continuous Monitoring

For long-running applications:

```python
class PrivacyMonitor:
    """Continuous privacy monitoring for production applications."""
    
    def __init__(self, host, check_interval=300, risk_threshold=0.7):
        self.host = host
        self.collector = MetadataCollector(host)
        self.check_interval = check_interval  # seconds
        self.risk_threshold = risk_threshold
        self.alerts = []
    
    async def start(self):
        """Start continuous monitoring."""
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self._monitor_loop)
    
    async def _monitor_loop(self):
        """Periodic privacy checks."""
        while True:
            await trio.sleep(self.check_interval)
            await self._check_privacy()
    
    async def _check_privacy(self):
        """Run privacy analysis and alert if needed."""
        analyzer = PrivacyAnalyzer(self.collector)
        report = analyzer.analyze()
        
        if report.overall_risk_score > self.risk_threshold:
            alert = {
                'timestamp': trio.current_time(),
                'risk_score': report.overall_risk_score,
                'risks': [r.description for r in report.risks]
            }
            self.alerts.append(alert)
            
            # Take action (log, notify, etc.)
            print(f"⚠️  Privacy Alert: Risk {report.overall_risk_score:.2f}")
            for risk in report.get_high_risks():
                print(f"   - {risk.description}")
    
    def get_statistics(self):
        """Get privacy statistics."""
        return {
            'total_alerts': len(self.alerts),
            'current_stats': self.collector.get_statistics(),
            'last_alert': self.alerts[-1] if self.alerts else None
        }

# Usage
async def main():
    host = new_host()
    monitor = PrivacyMonitor(host, check_interval=60, risk_threshold=0.7)
    
    network = host.get_network()
    async with background_trio_service(network):
        await network.listen(Multiaddr("/ip4/0.0.0.0/tcp/4001"))
        
        # Start monitoring in background
        async with trio.open_nursery() as nursery:
            nursery.start_soon(monitor.start)
            nursery.start_soon(run_your_application, host)
```

---

## Best Practices

### 1. Lifecycle Management

**✅ DO:**
```python
# Always use background_trio_service for lifecycle management
async with background_trio_service(host.get_network()):
    # Network is active here
    pass
# Network is properly cleaned up here
```

**❌ DON'T:**
```python
# Don't manage network lifecycle manually
network = host.get_network()
await network.run()  # Wrong - hard to clean up properly
```

### 2. Timeout Protection

**✅ DO:**
```python
# Always add timeouts to network operations
with trio.fail_after(10):  # 10 second timeout
    await host.connect(peer_info)

with trio.fail_after(5):  # 5 second timeout
    await network.listen(listen_addr)
```

**❌ DON'T:**
```python
# Don't call network operations without timeouts
await host.connect(peer_info)  # Could hang forever
```

### 3. Error Handling

**✅ DO:**
```python
try:
    with trio.fail_after(10):
        await host.connect(peer_info)
except trio.TooSlowError:
    print("Connection timeout")
except Exception as e:
    print(f"Connection failed: {e}")
```

**❌ DON'T:**
```python
# Don't ignore network errors
await host.connect(peer_info)  # Unhandled exceptions
```

### 4. Resource Cleanup

**✅ DO:**
```python
async with background_trio_service(network):
    # Use network
    pass

# Always close host when done
await host.close()
```

**❌ DON'T:**
```python
# Don't leave resources open
# (missing host.close() and context management)
```

### 5. Use Utility Functions

**✅ DO:**
```python
from libp2p_privacy_poc.utils import get_peer_listening_address

# Use helper to get full peer address
peer_addr = get_peer_listening_address(host)
await other_host.connect(info_from_p2p_addr(peer_addr))
```

**❌ DON'T:**
```python
# Don't duplicate this pattern everywhere
listener_key = list(network.listeners.keys())[0]
listener = network.listeners[listener_key]
actual_addr = listener.get_addrs()[0]
# ... etc (error-prone duplication)
```

---

## Performance Considerations

### Memory Usage

The `MetadataCollector` stores metadata for all connections and events:

```python
# Check memory usage
stats = collector.get_statistics()
print(f"Unique peers: {stats['unique_peers']}")
print(f"Total connections: {stats['total_connections']}")

# For long-running applications, consider periodic cleanup
if stats['total_connections'] > 10000:
    # Reset or archive old data
    collector.peers.clear()  # Caution: loses historical data
```

### CPU Usage

Privacy analysis complexity:
- **O(n)** for basic stats
- **O(n²)** for timing correlation analysis
- **O(n)** for risk detection

For large networks (100+ peers), consider:
```python
# Analyze less frequently
async def periodic_analysis(collector, interval=600):  # 10 minutes
    while True:
        await trio.sleep(interval)
        report = PrivacyAnalyzer(collector).analyze()
```

### Network Overhead

The `MetadataCollector` has **zero network overhead** - it only observes events:
- No additional protocol messages
- No extra connections
- No bandwidth usage
- Events are passively captured via `INotifee`

---

## Security Guidelines

### 1. Data Sensitivity

Privacy metadata can be sensitive:

```python
# ⚠️  Privacy reports contain network metadata
report = analyzer.analyze()

# Be careful with logging/storage
# DON'T: log.info(report.to_json())  # May leak peer info

# DO: Log only aggregated statistics
stats = collector.get_statistics()
log.info(f"Connections: {stats['total_connections']}, "
         f"Risk: {report.overall_risk_score:.2f}")
```

### 2. Access Control

```python
# Protect privacy reports in multi-user systems
class PrivacyReportService:
    def __init__(self, host):
        self._collector = MetadataCollector(host)
        self._analyzer = PrivacyAnalyzer(self._collector)
    
    def get_report(self, user, auth_token):
        """Get privacy report with access control."""
        if not self._verify_access(user, auth_token):
            raise PermissionError("Unauthorized")
        
        return self._analyzer.analyze()
```

### 3. ZK Proof Disclaimer

**IMPORTANT:** The current ZK proof system is **mock only**:

```python
from libp2p_privacy_poc.mock_zk_proofs import MockZKProofSystem

# ⚠️  NOT CRYPTOGRAPHICALLY SECURE
zk_system = MockZKProofSystem()
proof = zk_system.generate_anonymity_set_proof(...)

# DO NOT use for:
# - Production security
# - Real anonymity guarantees
# - Cryptographic applications

# OK to use for:
# - Demonstrations
# - Concept validation
# - Development/testing
```

---

## Advanced Usage

### Custom Risk Thresholds

```python
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer

# Customize risk thresholds for your use case
class CustomAnalyzer(PrivacyAnalyzer):
    def __init__(self, collector):
        super().__init__(collector)
        # Lower threshold for high-security applications
        self.ANONYMITY_SET_THRESHOLD = 10  # Default: 5
        self.TIMING_CORRELATION_THRESHOLD = 0.3  # Default: 0.5
```

### Selective Event Capture

```python
from libp2p_privacy_poc.metadata_collector import MetadataCollector

class SelectiveCollector(MetadataCollector):
    """Only capture events for specific peers."""
    
    def __init__(self, host, peer_allowlist=None):
        super().__init__(host)
        self.peer_allowlist = peer_allowlist or []
    
    def on_connection_opened(self, peer_id, multiaddr, direction):
        """Only capture if peer is in allowlist."""
        if not self.peer_allowlist or str(peer_id) in self.peer_allowlist:
            super().on_connection_opened(peer_id, multiaddr, direction)
```

### Integration with Monitoring Systems

```python
import trio
import json

async def export_metrics_to_prometheus(collector, port=9090):
    """Export privacy metrics to Prometheus."""
    # Pseudo-code - adapt for your monitoring system
    while True:
        await trio.sleep(30)  # Update every 30 seconds
        
        stats = collector.get_statistics()
        report = PrivacyAnalyzer(collector).analyze()
        
        metrics = {
            'privacy_risk_score': report.overall_risk_score,
            'total_connections': stats['total_connections'],
            'unique_peers': stats['unique_peers'],
            'high_risk_count': len(report.get_high_risks()),
            'critical_risk_count': len(report.get_critical_risks())
        }
        
        # Push to your monitoring system
        await push_metrics(metrics, port)
```

### Custom Report Formats

```python
from libp2p_privacy_poc.report_generator import ReportGenerator

class SlackReportGenerator(ReportGenerator):
    """Generate reports for Slack notifications."""
    
    def generate_slack_message(self, report):
        """Format report for Slack."""
        risk_emoji = "🔴" if report.overall_risk_score > 0.7 else \
                     "🟡" if report.overall_risk_score > 0.4 else "🟢"
        
        return {
            'text': f'{risk_emoji} Privacy Risk: {report.overall_risk_score:.2f}',
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f'*Risk Score:* {report.overall_risk_score:.2f}\n'
                                f'*Risks:* {len(report.risks)}'
                    }
                }
            ]
        }
```

---

## Troubleshooting

### Issue: No Events Captured

**Symptoms:**
```python
stats = collector.get_statistics()
print(stats['total_connections'])  # Output: 0
```

**Possible Causes:**

1. **Network not started:**
```python
# Fix: Use background_trio_service
async with background_trio_service(host.get_network()):
    # Network is active here
```

2. **No connections made:**
```python
# Fix: Actually connect to peers
peer_info = info_from_p2p_addr(peer_addr)
await host.connect(peer_info)
await trio.sleep(0.5)  # Allow time for event propagation
```

3. **Collector attached after network started:**
```python
# Fix: Attach collector BEFORE starting network
collector = MetadataCollector(host)  # Do this first
async with background_trio_service(host.get_network()):  # Then start
    # ...
```

### Issue: Connection Timeouts

**Symptoms:**
```
trio.TooSlowError: operation timed out
```

**Solutions:**

1. **Increase timeout:**
```python
with trio.fail_after(30):  # Longer timeout
    await host.connect(peer_info)
```

2. **Check peer is reachable:**
```python
# Verify peer address is valid and listener is running
print(f"Connecting to: {peer_multiaddr}")
```

3. **Wait for listener to start:**
```python
await network.listen(listen_addr)
await trio.sleep(0.5)  # Give listener time to bind
```

### Issue: High Memory Usage

**Symptoms:**
- Application memory grows over time
- Collector stores thousands of events

**Solutions:**

1. **Periodic cleanup:**
```python
async def cleanup_old_data(collector, interval=3600):
    """Clean up data older than 1 hour."""
    while True:
        await trio.sleep(interval)
        # Implementation depends on your retention policy
```

2. **Limit data retention:**
```python
from libp2p_privacy_poc.metadata_collector import MetadataCollector

class BoundedCollector(MetadataCollector):
    MAX_PEERS = 1000
    
    def on_connection_opened(self, peer_id, multiaddr, direction):
        if len(self.peers) >= self.MAX_PEERS:
            # Remove oldest peer
            oldest = min(self.peers.keys())
            del self.peers[oldest]
        super().on_connection_opened(peer_id, multiaddr, direction)
```

### Issue: Incorrect Risk Scores

**Symptoms:**
- Risk scores seem wrong for your use case
- Too many false positives

**Solutions:**

1. **Adjust thresholds:**
```python
analyzer = PrivacyAnalyzer(collector)
# Customize for your network characteristics
analyzer.ANONYMITY_SET_THRESHOLD = 10  # Higher threshold
```

2. **Filter noise:**
```python
# Only analyze significant connections
if stats['total_connections'] < 3:
    print("Not enough data for analysis")
else:
    report = analyzer.analyze()
```

---

## Production Checklist

Before deploying to production:

### ✅ Code Quality
- [ ] All timeout handlers implemented
- [ ] Error handling for all network operations
- [ ] Resource cleanup (host.close()) in place
- [ ] Memory limits configured
- [ ] Logging configured appropriately

### ✅ Security
- [ ] Privacy reports secured (access control)
- [ ] Sensitive data not logged
- [ ] ZK proofs marked as mock/demo
- [ ] Dependencies audited (run `pip audit`)

### ✅ Performance
- [ ] Analysis interval appropriate for load
- [ ] Memory usage monitored
- [ ] CPU usage acceptable
- [ ] No blocking operations in async code

### ✅ Testing
- [ ] Integration tests passing
- [ ] Edge cases tested (failures, timeouts, rapid ops)
- [ ] Load testing completed
- [ ] Real network validation done

### ✅ Monitoring
- [ ] Metrics exported (risk scores, connection counts)
- [ ] Alerts configured (high risk scores)
- [ ] Logs centralized
- [ ] Performance dashboards created

### ✅ Documentation
- [ ] API usage documented
- [ ] Configuration options documented
- [ ] Runbooks for common issues
- [ ] Team trained on privacy analysis

---

## Examples

See the `examples/` directory for complete working examples:

- **`basic_analysis.py`** - Simple 2-node connection analysis
- **`multi_node_scenario.py`** - 3-node star network with comparative analysis
- **`demo_scenarios.py`** - 5 comprehensive demonstration scenarios

All examples use real py-libp2p connections and follow the patterns in this guide.

---

## Further Reading

- **[Complete Documentation](DOCUMENTATION.md)** - Full API reference
- **[Known Issues](KNOWN_ISSUES.md)** - Current limitations
- **[py-libp2p Documentation](https://docs.libp2p.io/)** - Core libp2p concepts

---

## Support

If you encounter issues not covered in this guide:

1. Check [Known Issues](KNOWN_ISSUES.md)
2. Review test files in `tests/` for working examples
3. Examine `examples/` for reference implementations

---

**Last Updated:** Phase 1.5 Complete (November 2025)
**Status:** Production-Ready Patterns ✅ (Mock ZK only)

