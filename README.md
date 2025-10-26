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
# Console analysis with real network monitoring
libp2p-privacy analyze

# HTML report with ZK proofs
libp2p-privacy analyze --format html --with-zk-proofs --output report.html

# Run demonstrations
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

```bash
# Analyze privacy
libp2p-privacy analyze [OPTIONS]
  --format {console,json,html}
  --output PATH
  --with-zk-proofs
  --verbose

# Run demos
libp2p-privacy demo [OPTIONS]
  --scenario {all,timing,linkability,anonymity}

# Show version
libp2p-privacy version
```

## Project Structure

```
libp2p_privacy_poc/
├── libp2p_privacy_poc/      # Main package
│   ├── metadata_collector.py    # Event capture (430 lines)
│   ├── privacy_analyzer.py      # Privacy analysis (526 lines)
│   ├── mock_zk_proofs.py        # Mock ZK system (482 lines)
│   ├── report_generator.py      # Reports (423 lines)
│   ├── cli.py                   # CLI (370+ lines)
│   └── zk_integration.py        # ZK integration (419 lines)
├── examples/
│   └── basic_analysis.py        # Working example
├── tests/
│   └── test_basic_integration.py
├── README.md                    # This file
└── DOCUMENTATION.md             # Complete guide
```

## Documentation

📖 **[Complete Documentation](DOCUMENTATION.md)** - Everything you need:
- Detailed installation
- CLI usage guide
- Integration guide
- API documentation
- Architecture details
- Production roadmap
- Troubleshooting

## Example Output

```
Privacy Analysis Report
Overall Risk Score: 0.66/1.00
Risk Level: HIGH

Privacy Risks Detected: 3
  - CRITICAL: 0
  - HIGH: 1 (Small Anonymity Set)
  - MEDIUM: 1 (Timing Correlation)
  - LOW: 1 (Burst Pattern)

Recommendations:
1. Add random delays between connections
2. Connect to more peers to increase anonymity set
3. Implement timing obfuscation
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

**Phase 1: PoC** ✅ Complete
- ✅ Privacy analysis algorithms (6 detection methods)
- ✅ Real py-libp2p network integration
- ✅ Event capture via INotifee interface
- ✅ Mock ZK proof system
- ✅ CLI and reporting (console/JSON/HTML)
- ✅ Comprehensive documentation

**Phase 2: Real ZK Integration** (4-6 weeks)
- PySnark2 circuit implementation
- Groth16 proof generation and verification
- Trusted setup ceremony
- Performance optimization

**Phase 3: Production Hardening** (4-6 weeks)
- Professional security audit
- Performance testing at scale
- Memory and CPU optimization
- Production deployment guide
- Integration with py-libp2p core (optional)

## Contributing
Areas for contribution:
- Real ZK circuit design
- Privacy algorithm improvements
- Performance optimization
- Testing and validation

## Statistics

- **Code**: ~3,000 lines
- **Documentation**: 5 comprehensive files
- **Privacy Detection Algorithms**: 6 working methods
- **ZK Proof Types**: 4 (mock implementation)
- **Report Formats**: 3 (console/JSON/HTML)
- **Real Network Integration**: ✅ Working
- **Test Coverage**: Integration and unit tests
- **Phase 1 Completion**: 100%

## License

MIT License

---
