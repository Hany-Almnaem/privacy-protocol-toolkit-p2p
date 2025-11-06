# libp2p Privacy Analysis Tool

> **REAL py-libp2p Integration** ✅ | **Mock ZK Proofs** ⚠️ (demonstration only)

A privacy analysis tool that detects privacy leaks in **real py-libp2p network connections** and demonstrates zero-knowledge proof concepts.

**What's Real:**
- ✅ Full py-libp2p network integration with automatic event capture
- ✅ 6 privacy detection algorithms analyzing real network metadata
- ✅ Real TCP connections, timing analysis, and pattern detection

**What's Mock:**
- ⚠️ Zero-knowledge proofs (conceptual demonstration, not cryptographically secure)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Best Way to Get Started

**Jump straight to the examples!** They show everything working with real py-libp2p connections:

```bash
# Install
pip install -e .

# Run the basic 2-node example (30 seconds)
python examples/basic_analysis.py

# See real multi-node network analysis (1 minute)
python examples/multi_node_scenario.py
```

You'll see:
- ✅ Real libp2p hosts created
- ✅ Real TCP connections established
- ✅ `[PrivacyNotifee] Connected:` messages showing live captures
- ✅ Privacy analysis on actual network metadata
- ✅ Mock ZK proof generation

**For developers:** Check the [Python integration example](#use-in-python) below to integrate into your own py-libp2p applications.

---


## Quick Start

### Installation

```bash
cd libp2p_privacy_poc
pip install -e .
```

### See It In Action (Recommended)

**The best way to see real network analysis is through our examples:**

```bash
# 1. Basic 2-node real network analysis (30 seconds)
python examples/basic_analysis.py

# 2. Multi-node star network with 3 nodes (1 minute)
python examples/multi_node_scenario.py

# 3. All 5 demonstration scenarios with real connections (5 minutes)
python examples/demo_scenarios.py
```

These examples create **real py-libp2p hosts**, establish **real TCP connections**, and perform **actual privacy analysis** on live network metadata! 🚀

### CLI Usage

```bash
# Create a real libp2p host and monitor for connections
# (Note: This creates a host and listens, but needs peers to analyze)
libp2p-privacy analyze --duration 10

# To analyze actual traffic, connect to a peer:
libp2p-privacy analyze --connect-to /ip4/127.0.0.1/tcp/4001/p2p/QmPeer123...

# Generate reports in different formats
libp2p-privacy analyze --format html --output report.html
libp2p-privacy analyze --format json --with-zk-proofs --output report.json

# Use simulated data (for testing without network setup)
libp2p-privacy analyze --simulate

# Run all 5 demo scenarios (uses real connections)
libp2p-privacy demo
```

💡 **Tip**: For quick demonstrations, use the Python examples above. They automatically create connected nodes and show real analysis!

### Use in Python

```python
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from libp2p_privacy_poc import MetadataCollector, PrivacyAnalyzer
import trio

async def analyze_privacy():
    # Create libp2p host
    host = new_host()
    
    # Attach privacy collector (automatically captures events)
    collector = MetadataCollector(host)
    
    # Start network with proper lifecycle management
    async with background_trio_service(host.get_network()):
        # Your application runs here...
        # Collector automatically captures real network events
        
        # Analyze privacy
        report = PrivacyAnalyzer(collector).analyze()
        print(report.summary())

trio.run(analyze_privacy)
```

## What It Does

✅ **Privacy Leak Detection** - Identifies 6 types of privacy risks:
- Peer linkability
- Timing correlations
- Small anonymity sets
- Protocol fingerprinting
- Session tracking
- Connection patterns

✅ **Mock ZK Proofs** - Demonstrates ZK proof concepts:
- Anonymity set membership ("I'm one of N peers")
- Session unlinkability  
- Range proofs
- Timing independence

✅ **Multiple Report Formats** - Console, JSON, and HTML reports

## CLI Commands

### Analyze Command

Creates a real py-libp2p host, monitors network events, and runs privacy analysis.

```bash
libp2p-privacy analyze [OPTIONS]

Options:
  --duration SECONDS       Monitor duration in seconds (default: 30)
  --listen-addr MULTIADDR  Listen address (default: /ip4/127.0.0.1/tcp/0)
  --connect-to MULTIADDR   Peer multiaddr to connect to (optional but recommended)
  --format {console,json,html}  Output format (default: console)
  --output PATH            Output file (default: stdout)
  --with-zk-proofs         Include mock ZK proofs in report
  --verbose                Show detailed analysis
  --simulate               Use simulated data (for testing)

Examples:
  # Monitor an isolated host (will show "0 connections" but validates setup)
  libp2p-privacy analyze --duration 5

  # Analyze actual network traffic by connecting to a peer
  libp2p-privacy analyze --connect-to /ip4/127.0.0.1/tcp/4001/p2p/QmPeer...

  # Generate HTML report with ZK proofs
  libp2p-privacy analyze --format html --with-zk-proofs --output report.html

  # Quick test with simulated data (no real network needed)
  libp2p-privacy analyze --simulate --duration 3
```

💡 **Note**: For demonstrations with actual network traffic, **use the Python examples** (`python examples/basic_analysis.py`) which automatically create multiple connected nodes!

### Demo Command

```bash
# Run all demonstration scenarios with real networks
libp2p-privacy demo

# Each demo creates real py-libp2p connections
# - Scenario 1: Timing correlation detection
# - Scenario 2: Small anonymity set detection  
# - Scenario 3: Protocol fingerprinting
# - Scenario 4: Mock ZK proof showcase
# - Scenario 5: Comprehensive analysis
```

### Other Commands

```bash
# Show version
libp2p-privacy version
```

## Project Structure

```
libp2p_privacy_poc/
├── libp2p_privacy_poc/          # Main package
│   ├── metadata_collector.py   # Event capture via INotifee (430 lines)
│   ├── privacy_analyzer.py     # Privacy analysis (526 lines)
│   ├── mock_zk_proofs.py       # Mock ZK system (482 lines)
│   ├── report_generator.py     # Reports (423 lines)
│   ├── cli.py                  # CLI with real network support (450+ lines)
│   ├── zk_integration.py       # ZK integration (419 lines)
│   └── utils.py                # Utility functions
├── examples/
│   ├── basic_analysis.py       # Real 2-node connection example
│   ├── multi_node_scenario.py  # Real 3-node star network
│   └── demo_scenarios.py       # 5 comprehensive demos
├── tests/
│   ├── test_real_connection.py          # Real network tests
│   ├── test_edge_cases.py               # Edge case tests
│   ├── test_cli_real.py                 # CLI integration tests
│   ├── test_basic_integration.py        # Unit tests
│   └── test_integration_with_simulated_data.py  # Simulated tests
├── docs/
│   ├── DOCUMENTATION.md         # Complete guide
│   ├── PY_LIBP2P_STATUS.md     # Integration status
│   └── KNOWN_ISSUES.md         # Known limitations
├── README.md                    # This file (you are here)
└── requirements.txt            # Dependencies
```

## Documentation

📖 **[Complete Documentation](docs/DOCUMENTATION.md)** - Everything you need:
- Detailed installation
- CLI usage guide with real network examples
- Python integration guide
- API documentation
- Architecture details
- Production roadmap
- Troubleshooting

📖 **[Real Network Guide](docs/REAL_NETWORK_GUIDE.md)** - Production integration:
- Best practices for real networks
- Performance considerations
- Security guidelines
- Advanced usage patterns

📖 **[Known Issues](docs/KNOWN_ISSUES.md)** - Current limitations and workarounds

## Example Output

When you run `python examples/basic_analysis.py`, you'll see:

```
======================================================================
libp2p Privacy Analysis Tool - Basic Example
======================================================================

Using REAL py-libp2p connections with automatic event capture

1. Creating two libp2p hosts...
   Host1 ID: QmVhJVRSYHNSHgR9dJNbDxvKM5zDcX1ED7Bc1o7B...
   Host2 ID: QmT8RUDJd5KV8wAZHkiJEFPGvJqK2Rw7LcQxt9Md...

2. Creating MetadataCollector with automatic event capture...
   ✓ Collector attached (events will be auto-captured via INotifee)

3. Starting networks...
   ✓ Networks started

4. Starting listeners...
   ✓ Host2 listening on: /ip4/127.0.0.1/tcp/54321/p2p/QmT8R...

5. Establishing real connection...
   [PrivacyNotifee] Connected: QmT8R... via /ip4/127.0.0.1/tcp/54321
   ✓ Connection established!

6. Events captured by MetadataCollector:
   Total connections: 1
   Active connections: 1
   Unique peers: 1
   ✓ Real connection events captured successfully!

7. Running Privacy Analysis...
   Analysis Complete!
   - Overall Risk Score: 0.75/1.00
   - Risks Detected: 1
   - High Risks: 1

======================================================================
PRIVACY ANALYSIS REPORT
======================================================================
Overall Risk Score: 0.75/1.00
Risk Level: HIGH

PRIVACY RISKS DETECTED
  HIGH - Small Anonymity Set
    Small anonymity set: only 1 unique peers observed
    → Connect to more peers to increase anonymity set

8. Generating anonymity set proof...
   ✓ Proof generated
   Type: ZKProofType.ANONYMITY_SET_MEMBERSHIP
   Verification: ✓ Valid

✓ Analysis Complete!

💡 Key Achievement:
   - Real py-libp2p connections established and analyzed
   - Events automatically captured via INotifee
   - Privacy analysis performed on real network metadata
   - Ready for production integration!
```

## Requirements

- Python 3.9+
- py-libp2p 0.3.0+ (install from GitHub main branch recommended)
- See `requirements.txt` for all dependencies

### Installation Note

For best results, install the latest py-libp2p from GitHub:

```bash
pip install git+https://github.com/libp2p/py-libp2p.git@main
```

## Important Disclaimers

⚠️ **This is a Proof of Concept**

- **Real Network Integration**: ✅ Works with live py-libp2p connections
- **Mock ZK Proofs**: ⚠️ No cryptographic guarantees (demonstration only)
- **No Security Audit**: Not audited for production use
- **Heuristic Detection**: Privacy analysis uses pattern-based algorithms
- **Not Production Ready**: Requires real ZK implementation and security audit

**DO NOT use in production without:**
- Real ZK implementation (PySnark2/Groth16)
- Professional security audit
- Performance optimization and testing
- Comprehensive threat modeling
- Privacy guarantees validation

## Roadmap

**Phase 1: PoC with Real Network Integration** ✅ Complete
- ✅ Privacy analysis algorithms (6 detection methods)
- ✅ Real py-libp2p network integration throughout
- ✅ Automatic event capture via INotifee interface
- ✅ Mock ZK proof system (4 proof types)
- ✅ CLI with real network support
- ✅ Multiple report formats (console/JSON/HTML)
- ✅ Comprehensive test suite (unit + integration + edge cases)
- ✅ Production-ready examples (basic, multi-node, 5 scenarios)
- ✅ Complete documentation

**Phase 1.5: Real Network Validation** ✅ Complete
- ✅ All examples converted to real connections
- ✅ CLI defaults to real network analysis
- ✅ Edge case testing (failures, reconnections, rapid ops)
- ✅ CLI integration tests (13 comprehensive tests)
- ✅ Performance validation with real networks
- ✅ Documentation updated for production use

**Phase 2: Real ZK Integration** (4-6 weeks)
- PySnark2 circuit implementation
- Groth16 proof generation and verification
- Trusted setup ceremony
- Performance optimization
- Real cryptographic guarantees

**Phase 3: Production Hardening** (4-6 weeks)
- Professional security audit
- Performance testing at scale (100+ peers)
- Memory and CPU optimization
- Production deployment guide
- Optional integration with py-libp2p core

## Contributing
Areas for contribution:
- Real ZK circuit design
- Privacy algorithm improvements
- Performance optimization
- Testing and validation

## Statistics

- **Code**: ~3,500+ lines
- **Documentation**: 5 comprehensive files
- **Privacy Detection Algorithms**: 6 working methods
- **ZK Proof Types**: 4 (mock implementation)
- **Report Formats**: 3 (console/JSON/HTML)
- **Real Network Integration**: ✅ Fully Validated
- **Test Coverage**: 
  - Unit tests ✅
  - Integration tests ✅
  - Edge case tests (5 scenarios) ✅
  - CLI tests (13 comprehensive tests) ✅
  - Real network validation ✅
- **Examples**: 3 files, 7 scenarios, all using real connections
- **CLI**: Real network support with multiple options
- **Phase 1 Completion**: 100%
- **Phase 1.5 Completion**: 100%

## License

MIT License

---
