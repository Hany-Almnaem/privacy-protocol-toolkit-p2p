# Known Issues

## py-libp2p Connection Issue

### Status: ✅ RESOLVED (October 26, 2025)

**Original Issue**: py-libp2p node-to-node connections were failing due to improper network lifecycle initialization.

**Resolution**: Successfully integrated using the `background_trio_service()` pattern from `libp2p.tools.async_service`.

---

## Original Problem

### Description

Attempts to establish connections between two hosts resulted in:

```
SwarmException: unable to connect to [peer_id], no addresses established a successful connection
AttributeError: 'Swarm' object has no attribute '_manager'
```

### Root Cause

The py-libp2p `Swarm` class inherits from `Service` (in `libp2p/tools/async_service/base.py`) and requires proper lifecycle management through a `Manager` object. Calling `network.run()` directly did not initialize the required `_manager` attribute.

**Why it failed**:
```python
# ❌ This doesn't work
network = host.get_network()
await network.run()  # Fails: '_manager' attribute not set
```

**Root issue**: The `Service` base class requires `_manager` to be set before `run()` is called, but calling it directly skips this initialization step.

---

## The Solution ✅

### Using `background_trio_service()`

The correct approach is to use the `background_trio_service()` context manager, which:
1. Creates a `TrioManager` instance
2. Properly initializes `service._manager`
3. Manages the complete service lifecycle

**Working pattern**:
```python
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from multiaddr import Multiaddr
import trio

async def connect_nodes():
    # Create hosts
    host1 = new_host(listen_addrs=[Multiaddr("/ip4/127.0.0.1/tcp/10000")])
    host2 = new_host(listen_addrs=[Multiaddr("/ip4/127.0.0.1/tcp/10001")])
    
    # Start networks with proper lifecycle management
    async with background_trio_service(host1.get_network()):
        async with background_trio_service(host2.get_network()):
            # Networks are now active
            # Listeners started automatically
            
            # Connect nodes
            await host2.connect(peer_info)  # Works! ✅
            
            # Your application code here...
```

### What `background_trio_service()` Does

Found in `libp2p/tools/async_service/trio_service.py`:

```python
async def background_trio_service(service: ServiceAPI):
    async with trio.open_nursery() as nursery:
        manager = TrioManager(service)  # ← Creates manager
        # Sets service._manager internally
        nursery.start_soon(manager.run)  # ← Runs via manager
        await manager.wait_started()
        try:
            yield manager
        finally:
            await manager.stop()
```

**Key benefits**:
- Proper `_manager` initialization
- Automatic lifecycle management (start/stop)
- Clean resource cleanup
- Standard pattern used in all py-libp2p tests

---

## Verification

### Test Results

**Test**: `test_real_connection.py`

```
✅ Listeners started successfully (Host1: 1, Host2: 1)
✅ Real TCP connection established
✅ PrivacyNotifee captured connection events
✅ MetadataCollector collecting data
✅ Privacy analysis running successfully
```

**Exit code**: 0 (Success)

### Evidence

```bash
Host1 listeners: 1
Host2 listeners: 1
✅ SUCCESS! Listeners started!
✅ CONNECTION SUCCESSFUL!
[PrivacyNotifee] Connected: QmUDbahn... via None
Risk Score: 0.75
Risks Detected: 1
🎉 COMPLETE SUCCESS - READY FOR PRODUCTION!
```

---

## Current Status

### What Works ✅

- ✅ Real py-libp2p node-to-node connections
- ✅ Network listeners start properly
- ✅ Event capture via INotifee interface
- ✅ MetadataCollector captures real connection events
- ✅ Privacy analysis on live network data
- ✅ All report formats (console/JSON/HTML)
- ✅ CLI commands working with real networks

### Implementation Details

**Python Version**: 3.13  
**py-libp2p Version**: 0.3.0 (latest from GitHub main branch)  
**OS**: macOS (darwin 25.0.0)  
**Architecture**: x86_64 (Intel)

**Key Dependencies**:
- ✅ GMP library installed (via Homebrew)
- ✅ fastecdsa working
- ✅ trio async library
- ✅ All Python packages installed

---

## Integration Pattern for Users

### Basic Integration

```python
import trio
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from libp2p_privacy_poc import MetadataCollector, PrivacyAnalyzer

async def main():
    host = new_host()
    collector = MetadataCollector(host)
    
    async with background_trio_service(host.get_network()):
        # Your application runs here
        # Events are automatically captured
        
        # Analyze privacy
        report = PrivacyAnalyzer(collector).analyze()
        print(report.summary())

trio.run(main)
```

### Advanced: With Listeners

```python
async def main():
    listen_addr = Multiaddr("/ip4/0.0.0.0/tcp/4001")
    host = new_host(listen_addrs=[listen_addr])
    collector = MetadataCollector(host)
    
    async with background_trio_service(host.get_network()):
        await host.get_network().listen(listen_addr)
        
        # Wait for connections...
        await trio.sleep(300)  # 5 minutes
        
        # Analyze
        report = PrivacyAnalyzer(collector).analyze()
        print(report.summary())
```

---

## Lessons Learned

1. **Always use `background_trio_service()`** for py-libp2p network lifecycle
2. **Don't call `network.run()` directly** - it skips required initialization
3. **Study py-libp2p test suite** (`tests/utils/factories.py`) for patterns
4. **Service-based components need Managers** - this is an `async_service` pattern

---

## References

- **Solution Source**: `libp2p/tools/async_service/trio_service.py`
- **Usage Examples**: `tests/utils/factories.py` (SwarmFactory.create_and_listen)
- **Test Script**: `test_real_connection.py`
- **Documentation**: [DOCUMENTATION.md](DOCUMENTATION.md)

---

**Status**: ✅ Issue fully resolved  
**Date**: October 26, 2025  
**Phase 1**: Complete with real network integration
