# Complete Documentation

> **Current Status**: Proof of Concept - Real Network Integration ✅
> 
> This tool performs privacy analysis on **real py-libp2p network connections**. All privacy detection algorithms, event capture, and reporting features are functional. ZK proofs are mock implementations for demonstration purposes. See [Phase 2 Roadmap](#production-roadmap) for real ZK integration plans.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [CLI Usage](#cli-usage)
4. [Python Integration](#python-integration)
5. [Architecture](#architecture)
6. [Privacy Analysis](#privacy-analysis)
7. [ZK Proofs](#zk-proofs)
8. [Production Roadmap](#production-roadmap)
9. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.9 or higher
- Virtual environment (recommended)
- py-libp2p 0.3.0 or later (latest from GitHub recommended)

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd libp2p_privacy_poc

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install latest py-libp2p from GitHub (recommended)
pip install git+https://github.com/libp2p/py-libp2p.git@main

# Install in development mode
pip install -e .
```

This installs:
- All required dependencies including py-libp2p
- The `libp2p-privacy` CLI command
- The Python package for import
- Real network integration capabilities

### Verify Installation

```bash
# Check CLI is available
libp2p-privacy --help

# Run quick test
libp2p-privacy demo
```

---

## Quick Start

### 1. Run Your First Analysis

```bash
libp2p-privacy analyze
```

This runs privacy analysis with real network monitoring and displays results in your terminal.

### 2. Generate HTML Report

```bash
libp2p-privacy analyze --format html --output my_report.html
```

Open `my_report.html` in your browser to see a professional report.

### 3. Include ZK Proofs

```bash
libp2p-privacy analyze --with-zk-proofs
```

Adds mock zero-knowledge proofs to demonstrate privacy concepts (not cryptographically secure).

### 4. Use in Python Code

```python
import trio
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from libp2p_privacy_poc import MetadataCollector, PrivacyAnalyzer

async def main():
    # Create your libp2p host
    host = new_host()
    
    # Attach privacy collector (automatically captures events)
    collector = MetadataCollector(host)
    
    # Start network with proper lifecycle management
    async with background_trio_service(host.get_network()):
        # Your application runs here...
        # Collector automatically captures real network events
        
        # Analyze privacy
        analyzer = PrivacyAnalyzer(collector)
        report = analyzer.analyze()
        
        # Display results
        print(report.summary())
        print(f"Risk Score: {report.overall_risk_score:.2f}")

trio.run(main)
```

---

## CLI Usage

### Commands Overview

| Command | Description |
|---------|-------------|
| `analyze` | Run privacy analysis |
| `demo` | Run demonstration scenarios |
| `version` | Show version info |

### `analyze` - Privacy Analysis

**Basic Usage:**
```bash
libp2p-privacy analyze [OPTIONS]
```

Analyzes privacy leaks in **real py-libp2p network connections**. Creates a live network host, monitors connections for the specified duration, and performs privacy analysis on captured events.

**Options:**

**Network Configuration:**
- `--duration SECONDS` - How long to monitor network (default: 30)
- `--listen-addr MULTIADDR` - Listener address (default: /ip4/127.0.0.1/tcp/0)
- `--connect-to MULTIADDR` - Peer to connect to (optional)
- `--simulate` - Use simulated data instead of real network (for testing)

**Output Configuration:**
- `--format {console,json,html}` - Output format (default: console)
- `--output PATH` - Save report to file
- `--with-zk-proofs` - Include mock ZK proofs (demonstration only)
- `--verbose` - Detailed output

**Examples:**

```bash
# Quick analysis (5 seconds)
libp2p-privacy analyze --duration 5

# Standard analysis (30 seconds, default)
libp2p-privacy analyze

# Connect to a specific peer
libp2p-privacy analyze --connect-to /ip4/127.0.0.1/tcp/4001/p2p/QmPeer...

# Custom listen address
libp2p-privacy analyze --listen-addr /ip4/0.0.0.0/tcp/8000

# JSON for automation
libp2p-privacy analyze --format json --output report.json

# HTML for web viewing
libp2p-privacy analyze --format html --output report.html

# Full analysis with ZK proofs (JSON)
libp2p-privacy analyze --format json --with-zk-proofs --output full_report.json

# Simulated data (for testing/development)
libp2p-privacy analyze --simulate --duration 2
```

**Output Formats:**

1. **Console** - Colored terminal output with formatted sections
2. **JSON** - Machine-readable for automation and integration
3. **HTML** - Professional web report with styling

### `demo` - Demonstrations

**Basic Usage:**
```bash
libp2p-privacy demo
```

Runs **all 5 demonstration scenarios** with real py-libp2p networks:

**Scenarios:**

1. **Timing Correlation** - Shows how timing patterns leak privacy
   - Creates 3 real peers with specific timing patterns
   - Demonstrates timing correlation detection

2. **Small Anonymity Set** - Demonstrates anonymity set analysis
   - Creates 2 real peers (below threshold)
   - Shows high-risk anonymity detection

3. **Protocol Fingerprinting** - Shows protocol analysis
   - Creates multiple peers with different protocols
   - Demonstrates fingerprinting detection

4. **ZK Proof Showcase** - Mock ZK proof concepts (conceptual)
   - Demonstrates 4 types of mock ZK proofs
   - Shows anonymity set membership proofs

5. **Comprehensive Report** - Full analysis demonstration
   - Creates 4 real peers in complex network
   - Generates all report formats (console/JSON/HTML)
   - Includes mock ZK proofs

**Examples:**

```bash
# Run all demonstrations (takes ~2-3 minutes)
libp2p-privacy demo

# Skip slow tests in automated environments
SKIP_SLOW_TESTS=1 libp2p-privacy demo
```

**Note:** Each scenario creates real py-libp2p connections. Total runtime is approximately 2-3 minutes for all scenarios.

### `version` - Version Info

```bash
libp2p-privacy version
```

Displays version number and proof-of-concept disclaimer.

---

## Python Integration

**Current Mode**: Real network integration. The tool captures live events from py-libp2p connections via the INotifee interface.

### Basic Integration

#### Step 1: Import Components

```python
from libp2p_privacy_poc.metadata_collector import MetadataCollector
from libp2p_privacy_poc.privacy_analyzer import PrivacyAnalyzer
from libp2p_privacy_poc.report_generator import ReportGenerator
```

#### Step 2: Create Collector and Start Network

```python
import trio
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service

async def setup():
    # Create host
    host = new_host()
    
    # Attach collector (automatically registers INotifee)
    collector = MetadataCollector(host)
    
    # Start network with proper lifecycle management
    async with background_trio_service(host.get_network()):
        # Network is now active, events will be captured automatically
        # via INotifee interface - no manual calls needed!
        # Your application code here...
        pass
    
    return collector

# Note: For testing/simulation only (not recommended for production):
# You can manually report events without a real host
collector = MetadataCollector(libp2p_host=None)  # No real host
collector.on_connection_opened(peer_id, multiaddr, "outbound")  # Manual event
```

#### Step 3: Run Analysis

```python
# Create analyzer
analyzer = PrivacyAnalyzer(collector)

# Run analysis
report = analyzer.analyze()

# Access results
print(f"Risk Score: {report.overall_risk_score:.2f}")
print(f"Risks Found: {len(report.risks)}")

# Get specific risk types
critical_risks = report.get_critical_risks()
high_risks = report.get_high_risks()
```

#### Step 4: Generate Reports

```python
generator = ReportGenerator()

# Console report (colored)
console_report = generator.generate_console_report(report)
print(console_report)

# JSON report
json_report = generator.generate_json_report(report)
with open('report.json', 'w') as f:
    f.write(json_report)

# HTML report
html_report = generator.generate_html_report(report)
with open('report.html', 'w') as f:
    f.write(html_report)
```

### Advanced: With ZK Proofs

```python
from libp2p_privacy_poc.mock_zk_proofs import MockZKProofSystem

# Create ZK system
zk_system = MockZKProofSystem()

# Generate anonymity proof
peer_ids = list(collector.peers.keys())
if peer_ids:
    proof = zk_system.generate_anonymity_set_proof(
        peer_id=peer_ids[0],
        anonymity_set_size=len(peer_ids)
    )
    
    # Verify proof
    is_valid = zk_system.verify_proof(proof)
    print(f"Proof valid: {is_valid}")
    
    # Generate report with proofs
    zk_proofs = {"anonymity_set": [proof]}
    report_with_zk = generator.generate_html_report(report, zk_proofs)
```

### Event Handling

The tool automatically captures events when attached to a host. For manual control:

```python
# Manual event reporting
collector.on_connection_opened(
    peer_id="QmPeer123...",
    multiaddr=Multiaddr("/ip4/127.0.0.1/tcp/4001"),
    direction="outbound"
)

collector.on_connection_closed(peer_id, multiaddr)
collector.on_protocol_negotiated(peer_id, "/ipfs/id/1.0.0")
collector.on_stream_opened(peer_id)
```

### Periodic Monitoring

```python
import trio
import time

async def monitor_privacy(host, interval=300):
    """Monitor privacy every 5 minutes."""
    collector = MetadataCollector(host)
    analyzer = PrivacyAnalyzer(collector)
    
    while True:
        await trio.sleep(interval)
        
        report = analyzer.analyze()
        
        # Alert on critical risks
        if report.get_critical_risks():
            print(f"⚠️ Critical privacy risks detected!")
            # Send alert, log, etc.
        
        # Save report
        timestamp = int(time.time())
        with open(f'privacy_{timestamp}.html', 'w') as f:
            f.write(generator.generate_html_report(report))
```

---

## Architecture

### System Design

```
┌─────────────────┐
│  py-libp2p Host │
└────────┬────────┘
         │ Events
         ↓
┌─────────────────────┐
│ PrivacyNotifee      │ ← Implements INotifee
│ (Event Listener)    │
└────────┬────────────┘
         │
         ↓
┌─────────────────────┐
│ MetadataCollector   │ ← Stores connection data
│ - Connections       │
│ - Peers             │
│ - Timing data       │
└────────┬────────────┘
         │
         ↓
┌─────────────────────┐
│ PrivacyAnalyzer     │ ← Detects privacy leaks
│ - 6 detection algos │
│ - Risk scoring      │
└────────┬────────────┘
         │
         ↓
┌─────────────────────┐
│ ReportGenerator     │ ← Creates reports
│ - Console/JSON/HTML │
└─────────────────────┘
```

### Core Components

#### 1. MetadataCollector

**Purpose**: Captures privacy-relevant network events

**Key Features**:
- Automatic event hooking via INotifee pattern
- Connection lifecycle tracking
- Peer metadata aggregation
- Timing correlation data

**Data Structures**:
```python
@dataclass
class ConnectionMetadata:
    peer_id: str
    multiaddr: str
    direction: str
    timestamp_start: float
    protocols: List[str]
    # ... more fields

@dataclass
class PeerMetadata:
    peer_id: str
    first_seen: float
    connection_count: int
    multiaddrs: Set[str]
    protocols: Set[str]
```

#### 2. PrivacyAnalyzer

**Purpose**: Detects privacy leaks and calculates risk scores

**Detection Algorithms**:
1. Peer linkability (multiaddr reuse, protocol patterns)
2. Timing correlations (regular intervals, bursts)
3. Session unlinkability (cross-session tracking)
4. Anonymity set size (deanonymization risk)
5. Protocol fingerprinting (unique combinations)
6. Connection patterns (direction imbalances)

**Risk Levels**:
- **CRITICAL** (0.80-1.00): Severe leaks
- **HIGH** (0.60-0.79): Significant concerns
- **MEDIUM** (0.40-0.59): Moderate risks
- **LOW** (0.00-0.39): Minor considerations

#### 3. Mock ZK Proof System

**Purpose**: Demonstrate ZK proof concepts (not cryptographically secure!)

**Proof Types**:
```python
class ZKProofType(Enum):
    ANONYMITY_SET_MEMBERSHIP  # "I'm one of N peers"
    SESSION_UNLINKABILITY     # "Sessions can't be linked"
    RANGE_PROOF               # "Value is in range"
    TIMING_INDEPENDENCE       # "Timing doesn't leak"
```

⚠️ **Current implementation is for demonstration only** - uses hashing instead of real ZK circuits.

---

## Privacy Analysis

### What It Detects

#### 1. Peer Linkability

**Problem**: Multiple connections can be linked to the same peer.

**Detection Method**:
- Multiaddr reuse patterns
- Protocol combination uniqueness
- Connection timing correlation

**Severity Factors**:
- Number of unique addresses used
- Protocol set distinctiveness
- Temporal clustering

**Example**:
```
RISK: Peer Linkability
Severity: MEDIUM
Description: Peer QmPeer123... uses 3 multiaddrs
Confidence: 85%
Recommendation: Use different addresses for different sessions
```

#### 2. Timing Correlation

**Problem**: Predictable connection timing leaks identity.

**Detection Method**:
- Inter-connection interval analysis
- Coefficient of variation
- Burst pattern detection

**Risk Indicators**:
- Low variation in timing (CV < 0.3)
- Regular intervals
- Synchronized activity

**Example**:
```
RISK: Timing Correlation
Severity: HIGH
Description: Regular interval detected (CV: 0.02)
Confidence: 90%
Recommendation: Add random delays (0-5s)
```

#### 3. Small Anonymity Set

**Problem**: Few unique peers = easy deanonymization.

**Detection Method**:
- Count unique peer IDs
- Compare to recommended minimums

**Thresholds**:
- < 10 peers: CRITICAL
- < 50 peers: HIGH
- < 100 peers: MEDIUM

**Example**:
```
RISK: Small Anonymity Set
Severity: HIGH
Description: Only 15 unique peers observed
Confidence: 100%
Recommendation: Connect to more peers (target: 100+)
```

#### 4. Protocol Fingerprinting

**Problem**: Unique protocol combinations identify the node.

**Detection Method**:
- Analyze protocol usage patterns
- Calculate uniqueness score

**Risk Factors**:
- Rare protocol combinations
- Version-specific usage
- Non-standard protocols

#### 5. Session Unlinkability

**Problem**: Sessions can be linked across different times.

**Detection Method**:
- Cross-session protocol consistency
- Behavioral pattern matching

**Indicators**:
- Same protocols across sessions
- Similar timing patterns
- Consistent peer selection

#### 6. Connection Patterns

**Problem**: Consistent inbound/outbound ratios fingerprint node role.

**Detection Method**:
- Direction imbalance analysis
- Client vs server behavior

**Risk Levels**:
- > 80% one direction: HIGH
- > 60% one direction: MEDIUM

### Risk Scoring

**Overall Risk Score** = Weighted average of individual risks

**Weights**:
- Critical risks: 1.0
- High risks: 0.75
- Medium risks: 0.50
- Low risks: 0.25

**Formula**:
```python
score = sum(risk.confidence * weight) / total_risks
```

### Recommendations

The analyzer provides actionable recommendations:

1. **Add Random Delays** - For timing correlation issues
2. **Increase Anonymity Set** - Connect to more peers
3. **Use Connection Pooling** - Mask connection patterns
4. **Implement Timing Obfuscation** - Randomize intervals
5. **Rotate Addresses** - Prevent multiaddr linkability
6. **Diversify Protocols** - Avoid unique combinations

---

## ZK Proofs

### Current Implementation (Mock)

⚠️ **For demonstration and education only - NO cryptographic guarantees**

### Proof Types

#### 1. Anonymity Set Membership

**Claim**: "I am one of N peers" (without revealing which)

**Generation**:
```python
proof = zk_system.generate_anonymity_set_proof(
    peer_id="QmMyPeer...",
    anonymity_set_size=1000
)
```

**Real Implementation** (Future):
```python
# Using PySnark2 + Groth16
@snark
def anonymity_circuit(peer_id_hash, anonymity_set_hashes):
    # Prove peer_id_hash is in anonymity_set_hashes
    # Without revealing which one
    assert peer_id_hash in anonymity_set_hashes
```

#### 2. Session Unlinkability

**Claim**: "These two sessions cannot be linked"

**Generation**:
```python
proof = zk_system.generate_unlinkability_proof(
    session_1_id="session_abc",
    session_2_id="session_def"
)
```

**Real Implementation** (Future):
- Prove different session keys without revealing them
- Show independent timing patterns cryptographically

#### 3. Range Proofs

**Claim**: "My value is in range [min, max]" (without revealing exact value)

**Generation**:
```python
proof = zk_system.generate_range_proof(
    value_name="connection_count",
    min_value=10,
    max_value=100
)
```

**Use Cases**:
- Prove sufficient anonymity set size
- Show adequate connection count
- Demonstrate timing independence

### Production Roadmap

**Phase 2: Real ZK Implementation**

1. **Technology Stack**:
   - PySnark2 for Python ZK circuits
   - Groth16 proof system
   - BN254 elliptic curve

2. **Implementation Plan**:
   ```python
   # 1. Define circuits
   @snark
   def privacy_circuit(public_inputs, private_inputs):
       # Implement privacy proofs
       pass
   
   # 2. Setup trusted ceremony
   setup = generate_trusted_setup()
   
   # 3. Generate proofs
   proof = generate_proof(circuit, public_in, private_in, setup)
   
   # 4. Verify
   is_valid = verify_proof(proof, public_inputs, setup)
   ```

3. **Performance Targets**:
   - Proof generation: < 1 second
   - Proof verification: < 100ms
   - Proof size: < 200 bytes

4. **Timeline**: 4-6 weeks minimum

---

## Full Roadmap

### Current Status: Phase 1 Complete ✅

- ✅ Core privacy analysis (6 detection algorithms)
- ✅ Real py-libp2p network integration via INotifee
- ✅ Event capture from live connections
- ✅ Mock ZK proof system (demonstration)
- ✅ CLI tool with 3 commands
- ✅ Multi-format reports (console/JSON/HTML)
- ✅ Python integration API with background_trio_service
- ✅ Comprehensive documentation

**Achievement**: Successfully integrated with py-libp2p using the `background_trio_service()` pattern for proper network lifecycle management.

### Phase 2: Real ZK Integration (4-6 weeks) 

**Goals**:
- Replace mock ZK with real cryptographic proofs
- PySnark2 + Groth16 implementation
- Performance optimization

**Deliverables**:
1. Real anonymity set membership proofs
2. Real session unlinkability proofs
3. Real range proofs
4. Cryptographic verification
5. Performance benchmarks

**Technical Requirements**:
- PySnark2 library integration
- Trusted setup ceremony
- Circuit optimization
- Gas cost analysis

### Phase 3: Production Hardening

**Goals**:
- Security audit
- Production deployment
- Performance at scale

**Deliverables**:
1. Security audit report
2. Performance benchmarks 
3. Production deployment guide
4. Monitoring and alerting
5. py-libp2p core integration (optional)

**Requirements**:
- Professional security audit
- Load testing
- Memory profiling
- Production documentation

### Phase 4: Advanced Features (Future)

**Possible Additions**:
- Machine learning-based detection
- Real-time streaming analysis
- Privacy-preserving protocols
- Mobile ZK (mopro integration)
- Cross-chain privacy
- Advanced visualization
- Privacy certification system

---

## Troubleshooting

### Installation Issues

**Problem**: `libp2p-privacy command not found`

**Solution**:
```bash
# Ensure you're in virtual environment
source venv/bin/activate

# Reinstall
pip install -e .

# Or use module directly
python -m libp2p_privacy_poc.cli analyze
```

**Problem**: Import errors for dependencies

**Solution**:
```bash
pip install -r requirements.txt
pip install -e .
```

**Problem**: GMP library not found (macOS)

**Solution**:
```bash
# Install GMP for your architecture
brew install gmp

# Reinstall fastecdsa
pip uninstall fastecdsa
LDFLAGS="-L/usr/local/lib" CFLAGS="-I/usr/local/include" pip install fastecdsa
```

### Runtime Issues

**Problem**: No events being captured

**Solution**:
1. Verify notifee is registered:
   ```python
   network = host.get_network()
   print(network.notifees)  # Should include PrivacyNotifee
   ```

2. Use manual event reporting:
   ```python
   collector = MetadataCollector(libp2p_host=None)
   collector.on_connection_opened(...)
   ```

**Problem**: Analysis takes too long

**Solution**:
```python
# Analyze recent data only
report = analyzer.analyze_recent(time_window=300)  # Last 5 min

# Or limit data size
collector.connection_history = collector.connection_history[-1000:]
```

**Problem**: Memory usage growing

**Solution**:
```python
# Periodic cleanup
def cleanup_old_data(collector, max_age_hours=1):
    cutoff = time.time() - (max_age_hours * 3600)
    collector.connection_history = [
        c for c in collector.connection_history
        if c.timestamp_start > cutoff
    ]
```

### Common Errors

**Error**: `TypeError: PrivacyReport.__init__() missing required argument`

**Cause**: Outdated code

**Fix**: Update to latest version or initialize with:
```python
report = PrivacyReport(
    timestamp=time.time(),
    overall_risk_score=0.0
)
```

**Error**: `AttributeError: 'list' object has no attribute 'values'`

**Cause**: ZK proofs passed as list instead of dict

**Fix**:
```python
# Wrong
zk_proofs = [proof1, proof2]

# Correct
zk_proofs = {"anonymity_set": [proof1, proof2]}
```

---

## Statistics

- **Total Code**: ~3,000 lines
- **Core Modules**: 7 (all functional)
- **CLI Commands**: 3 (analyze, demo, version)
- **Report Formats**: 3 (console/JSON/HTML)
- **Privacy Detection Algorithms**: 6 working methods
- **ZK Proof Types**: 4 (mock implementation)
- **Examples**: 3 complete examples + integration tests
- **Real Network Integration**: ✅ Working
- **Phase 1 Completion**: 100%

--- 
**Version**: 0.1.0 (Proof of Concept)  
**Last Updated**: October 26, 2025  

