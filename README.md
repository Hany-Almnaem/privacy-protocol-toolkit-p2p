# libp2p Privacy Analysis Tool

> ⚠️ **PROOF OF CONCEPT** - Mock ZK proofs for demonstration only

A privacy analysis tool for py-libp2p that detects privacy leaks in real network connections and demonstrates zero-knowledge proof concepts.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


## Quick Start

### Installation

```bash
cd libp2p_privacy_poc
pip install -e .
```

### Run Analysis

```bash
# Start real network analysis (monitors for 30 seconds by default)
libp2p-privacy analyze

# Short analysis (3 seconds)
libp2p-privacy analyze --duration 3

# Connect to a specific peer and analyze
libp2p-privacy analyze --connect-to /ip4/127.0.0.1/tcp/4001/p2p/QmPeer123...

# HTML report with ZK proofs
libp2p-privacy analyze --format html --with-zk-proofs --output report.html

# Use simulated data (for testing/development)
libp2p-privacy analyze --simulate

# Run all 5 demonstration scenarios
libp2p-privacy demo
```

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

### Analyze Command (Real Network)

```bash
# Analyze privacy with real py-libp2p network
libp2p-privacy analyze [OPTIONS]

Options:
  --duration SECONDS       Analysis duration (default: 30)
  --listen-addr MULTIADDR  Listen address (default: /ip4/127.0.0.1/tcp/0)
  --connect-to MULTIADDR   Peer to connect to (optional)
  --format {console,json,html}  Output format (default: console)
  --output PATH            Output file (default: stdout)
  --with-zk-proofs         Include mock ZK proofs in report
  --verbose                Show detailed analysis
  --simulate               Use simulated data (for testing)

Examples:
  # Quick 5-second analysis
  libp2p-privacy analyze --duration 5

  # Connect to peer and analyze
  libp2p-privacy analyze --connect-to /ip4/127.0.0.1/tcp/4001/p2p/QmPeer...

  # Generate HTML report
  libp2p-privacy analyze --format html --output report.html

  # Full analysis with ZK proofs (JSON)
  libp2p-privacy analyze --with-zk-proofs --format json --output report.json
```

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

```
====================================================================
libp2p Privacy Analysis Tool - Real Network Monitoring
====================================================================

Starting REAL py-libp2p network...
  Host ID: QmVhJVRSYHNSHgR9dJNbDxvKM5zDcX1ED7Bc1o7B...
  Listening on: /ip4/127.0.0.1/tcp/54321

Monitoring network for 30 seconds...
  Events captured: 5 connections, 12 streams
  Unique peers: 3

Running Privacy Analysis...

====================================================================
PRIVACY ANALYSIS REPORT
====================================================================
Overall Risk Score: 0.66/1.00
Risk Level: HIGH

Privacy Risks Detected: 3
  ⚠️  HIGH: Small Anonymity Set (3 peers - below threshold of 5)
  ⚠️  MEDIUM: Timing Correlation (45% correlation in connection patterns)
  ⚠️  LOW: Connection Burst Pattern (0.2s average interval)

NETWORK STATISTICS
  Total connections: 5
  Active connections: 3
  Unique peers: 3
  Protocols used: 2 [/ipfs/ping/1.0.0, /ipfs/id/1.0.0]
  Listening addresses: 2

RECOMMENDATIONS
  1. Add random delays between connections
  2. Connect to more peers to increase anonymity set (target: 10+)
  3. Implement timing obfuscation
  4. Use connection pooling to mask patterns

✓ Analysis Complete!
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
- **Documentation**: 6 comprehensive files
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
